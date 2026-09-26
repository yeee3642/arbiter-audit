"""Quality benchmark core: fairness refusals, shared calibration, and claims."""

from __future__ import annotations

import hashlib
import json

import pandas as pd
import pytest

from bastet_cc.aggregate import Calibration
from bastet_cc.hermes import HERMES_VERSION
from bastet_cc.quality_benchmark import (
    BenchmarkArm,
    audit_execution,
    benchmark_quality,
    freeze_calibration,
)
from bastet_cc.twincourt import (
    OVERLAY_SCHEMA_VERSION,
    TWINCOURT_PROMPT_VERSION,
    TWINCOURT_SCHEMA_VERSION,
    TWINCOURT_TREATMENT,
    TWINCOURT_VERSION,
)


def _automation(
    *,
    endpoint: str = "https://llm-api.zoolab.org/v1",
    provider_mode: str = "live",
    budget: dict | None = None,
) -> dict:
    payload = {
        "experiment_id": "experiment-1",
        "subject_id": "subject-1",
        "endpoint": endpoint,
        "model": "ais3/llama-3.1-8b",
        "provider_mode": provider_mode,
        "selected_workflow": "flashloan",
        "workflow_sha256": "workflow-sha",
        "prompt_sha256": "prompt-sha",
        "profile_version": "ais3-fair-ab-v2",
        "adapter_version": "dual-surface-v2",
        "schema_version": "bastet-audit-v1",
        "budget": budget or {
            "global_calls": 20,
            "global_tokens": 200_000,
            "per_arm_calls": 10,
            "per_arm_tokens": 100_000,
        },
        "claim_level": (
            "pipeline-readiness-only"
            if provider_mode == "mock"
            else "live-provider-evidence"
        ),
    }
    canonical = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return {
        **payload,
        "fingerprint": hashlib.sha256(canonical.encode()).hexdigest(),
        "evidence_complete": True,
    }


def _manifest(*, run_id: str, split: str = "dev", repos: list[str] | None = None,
              model: str = "ais3/llama-3.1-8b", base_url: str | None = "https://llm.example/v1",
              splits_sha256: str = "split-sha", planned_tasks: int = 1,
              automation: dict | None = None,
              quality_treatment: str | None = None) -> dict:
    treatment = quality_treatment
    if treatment is None:
        treatment = TWINCOURT_TREATMENT if run_id in {"b", "run-b"} else "none"
    provider_fingerprint = (
        automation.get("fingerprint")
        if isinstance(automation, dict)
        else hashlib.sha256(b"provider-profile-1").hexdigest()
    )
    plan_sha = hashlib.sha256(
        f"plan-{planned_tasks}".encode()).hexdigest()
    manifest = {
        "run_id": run_id,
        "arm": "routed",
        "model": model,
        "target": split,
        "repos": repos or ["r1", "r2"],
        "splits_sha256": splits_sha256,
        "planned_tasks": planned_tasks,
        "task_plan_sha256": plan_sha,
        "execution": {
            "planned_tasks": planned_tasks,
            "completed_tasks": planned_tasks,
            "successful_tasks": planned_tasks,
            "failed_tasks": 0,
            "missing_tasks": 0,
            "unexpected_tasks": 0,
            "invalid_result_rows": 0,
            "error_counts": {},
            "planned_task_ids_sha256": plan_sha,
            "completed_task_ids_sha256": plan_sha,
            "scan_completed": True,
        },
        "prompt_version": "v1",
        "detectors": 79,
        "verify": True,
        "closure": False,
        "provider_profile": {"fingerprint": provider_fingerprint},
        "quality_treatment": treatment,
        "quality_budget_chars": 24_000,
        "quality_versions": ({
            "hermes": HERMES_VERSION,
            "twincourt": TWINCOURT_VERSION,
            "twincourt_prompt": TWINCOURT_PROMPT_VERSION,
            "twincourt_schema": TWINCOURT_SCHEMA_VERSION,
            "overlay_schema": OVERLAY_SCHEMA_VERSION,
        } if treatment == TWINCOURT_TREATMENT else None),
    }
    if base_url is not None:
        manifest["base_url"] = base_url
    if automation is not None:
        manifest["automation"] = automation
    return manifest


def _truth(repos: list[str], positive_tag: str = "Slippage",
           positive_repos: list[str] | None = None) -> pd.DataFrame:
    wanted = set(positive_repos or repos[:1])
    rows = []
    for repo in repos:
        if repo in wanted:
            rows.append({"repo_path": repo, "tag": positive_tag, "status": "Done"})
            continue
        rows.append({"repo_path": repo, "tag": "", "status": "Done"})
    return pd.DataFrame(rows)


def _calibration() -> Calibration:
    return Calibration(
        detector_prior={},
        tau=0.5,
        verify_multiplier={"confirmed": 1.0, "unverified": 1.0,
                           "uncertain": 1.0, "rejected": 0.0},
        default_prior=1.0,
    )


def test_benchmark_scores_both_arms_and_marks_dev_as_exploratory(finding_factory):
    repos = ["r1", "r2"]
    truth = _truth(repos)
    calibration = freeze_calibration(_calibration(), source_run="calib-dev-1",
                                     source_split="dev")

    arm_a = BenchmarkArm(
        label="baseline",
        manifest=_manifest(run_id="run-a", repos=repos, planned_tasks=3),
        findings=[
            finding_factory(repo="r1", confidence=0.95, verdict="confirmed"),
            finding_factory(repo="r2", confidence=0.10),
        ],
        cost={"actual_calls": 2, "input_tokens": 30},
    )
    arm_b = BenchmarkArm(
        label="quality",
        manifest=_manifest(run_id="run-b", repos=repos, planned_tasks=3),
        findings=[],
        cost={"actual_calls": 5, "input_tokens": 75},
    )

    result = benchmark_quality(arm_a, arm_b, truth, calibration)

    assert result["audit"]["comparable"] is True
    assert result["audit"]["evidence"]["calibration_sha256"]["actual"] == calibration.sha256
    assert result["arms"]["a"]["quality"]["pooled"]["tp"] == 1
    assert result["arms"]["b"]["quality"]["pooled"]["fn"] == 1
    assert result["arms"]["a"]["verdicts"]["counts"]["confirmed"] == 1
    assert result["comparison"]["mcnemar"]["b"] == 1
    assert result["comparison"]["cost"]["actual_calls"]["delta"] == -3
    assert result["claim_status"] == "exploratory"


def test_refuses_endpoint_runs_when_base_url_differs(finding_factory):
    truth = _truth(["r1"])
    calibration = freeze_calibration(_calibration(), source_run="calib-dev-1",
                                     source_split="dev")

    result = benchmark_quality(
        BenchmarkArm("a", _manifest(run_id="a", repos=["r1"], base_url="https://a.example/v1"),
                     [finding_factory(repo="r1", confidence=0.9)]),
        BenchmarkArm("b", _manifest(run_id="b", repos=["r1"], base_url="https://b.example/v1"),
                     [finding_factory(repo="r1", confidence=0.9)]),
        truth,
        calibration,
    )

    assert result["claim_status"] == "unfair_comparison"
    assert result["audit"]["mode"] == "endpoint"
    assert result["audit"]["refusal"]["fairness_fields"]["base_url"]["status"] == "mismatch"


@pytest.mark.parametrize(
    ("treatment_a", "treatment_b"),
    [
        ("none", "none"),
        (TWINCOURT_TREATMENT, "none"),
        (TWINCOURT_TREATMENT, TWINCOURT_TREATMENT),
    ],
)
def test_refuses_wrong_or_swapped_quality_arm_roles(
    finding_factory, treatment_a, treatment_b
):
    repos = ["r1"]
    truth = _truth(repos)
    calibration = freeze_calibration(
        _calibration(), source_run="calib-dev-1", source_split="dev")

    result = benchmark_quality(
        BenchmarkArm(
            "a",
            _manifest(
                run_id="a",
                repos=repos,
                quality_treatment=treatment_a,
            ),
            [finding_factory(repo="r1", confidence=0.9)],
        ),
        BenchmarkArm(
            "b",
            _manifest(
                run_id="b",
                repos=repos,
                quality_treatment=treatment_b,
            ),
            [finding_factory(repo="r1", confidence=0.9)],
        ),
        truth,
        calibration,
    )

    assert result["claim_status"] == "unfair_comparison"
    assert result["audit"]["refusal"]["fairness_fields"][
        "quality_treatment_roles"
    ]["status"] == "mismatch"


@pytest.mark.parametrize(
    ("field", "value", "audit_field"),
    [
        ("quality_versions", None, "quality_versions"),
        ("quality_budget_chars", 12_000, "quality_budget_chars"),
        ("provider_profile", None, "provider_profile_fingerprint"),
    ],
)
def test_refuses_missing_or_mismatched_quality_evidence(
    finding_factory, field, value, audit_field
):
    repos = ["r1"]
    truth = _truth(repos)
    calibration = freeze_calibration(
        _calibration(), source_run="calib-dev-1", source_split="dev")
    manifest_b = _manifest(run_id="b", repos=repos)
    if value is None:
        manifest_b.pop(field)
    else:
        manifest_b[field] = value

    result = benchmark_quality(
        BenchmarkArm(
            "a",
            _manifest(run_id="a", repos=repos),
            [finding_factory(repo="r1", confidence=0.9)],
        ),
        BenchmarkArm(
            "b",
            manifest_b,
            [finding_factory(repo="r1", confidence=0.9)],
        ),
        truth,
        calibration,
    )

    assert result["claim_status"] == "unfair_comparison"
    assert audit_field in result["audit"]["refusal"]["fairness_fields"]


def test_refuses_automation_runs_when_budget_differs(finding_factory):
    truth = _truth(["r1"])
    calibration = freeze_calibration(_calibration(), source_run="calib-dev-1",
                                     source_split="dev")
    automation_a = _automation(
        budget={
            "global_calls": 20,
            "global_tokens": 200_000,
            "per_arm_calls": 10,
            "per_arm_tokens": 100_000,
        })
    automation_b = _automation(
        budget={
            "global_calls": 21,
            "global_tokens": 200_000,
            "per_arm_calls": 10,
            "per_arm_tokens": 100_000,
        })

    result = benchmark_quality(
        BenchmarkArm("a", _manifest(run_id="a", repos=["r1"], base_url=None,
                                     automation=automation_a),
                     [finding_factory(repo="r1", confidence=0.9)]),
        BenchmarkArm("b", _manifest(run_id="b", repos=["r1"], base_url=None,
                                     automation=automation_b),
                     [finding_factory(repo="r1", confidence=0.9)]),
        truth,
        calibration,
    )

    assert result["claim_status"] == "unfair_comparison"
    assert result["audit"]["mode"] == "automation"
    assert result["audit"]["refusal"]["fairness_fields"]["automation_budget"]["status"] == "mismatch"


def test_refuses_automation_runs_when_provider_endpoint_differs(finding_factory):
    truth = _truth(["r1"])
    calibration = freeze_calibration(
        _calibration(), source_run="calib-dev-1", source_split="dev")
    result = benchmark_quality(
        BenchmarkArm(
            "a",
            _manifest(
                run_id="a",
                repos=["r1"],
                base_url=None,
                automation=_automation(),
            ),
            [finding_factory(repo="r1", confidence=0.9)],
        ),
        BenchmarkArm(
            "b",
            _manifest(
                run_id="b",
                repos=["r1"],
                base_url=None,
                automation=_automation(
                    endpoint="https://other.example/v1"),
            ),
            [finding_factory(repo="r1", confidence=0.9)],
        ),
        truth,
        calibration,
    )

    assert result["claim_status"] == "unfair_comparison"
    assert result["audit"]["refusal"]["fairness_fields"][
        "automation_endpoint"
    ]["status"] == "mismatch"


def test_top_level_fingerprint_cannot_replace_missing_automation_fingerprint(
    finding_factory,
):
    repos = ["r1"]
    truth = _truth(repos)
    calibration = freeze_calibration(
        _calibration(), source_run="calib-dev-1", source_split="dev")
    common = _automation()
    manifest_a = _manifest(
        run_id="a", repos=repos, base_url=None, automation=dict(common))
    manifest_b = _manifest(
        run_id="b", repos=repos, base_url=None, automation=dict(common))
    del manifest_b["automation"]["fingerprint"]
    manifest_b["fingerprint"] = "fp-1"

    result = benchmark_quality(
        BenchmarkArm(
            "a", manifest_a, [finding_factory(repo="r1", confidence=0.9)]),
        BenchmarkArm(
            "b", manifest_b, [finding_factory(repo="r1", confidence=0.9)]),
        truth,
        calibration,
    )

    assert result["claim_status"] == "unfair_comparison"
    assert result["audit"]["refusal"]["fairness_fields"][
        "automation_fingerprint"
    ]["status"] == "missing"


def test_noncanonical_automation_budget_is_never_fair_evidence(finding_factory):
    repos = ["r1"]
    truth = _truth(repos)
    calibration = freeze_calibration(
        _calibration(), source_run="calib-dev-1", source_split="dev")
    invalid = {
        "fingerprint": "fp-1",
        "budget": {"max_requests": 20},
        "subject_id": "subject-1",
        "endpoint": "https://llm-api.zoolab.org/v1",
        "provider_mode": "live",
        "claim_level": "live-provider-evidence",
    }

    result = benchmark_quality(
        BenchmarkArm(
            "a",
            _manifest(
                run_id="a", repos=repos, base_url=None,
                automation=dict(invalid)),
            [finding_factory(repo="r1", confidence=0.9)],
        ),
        BenchmarkArm(
            "b",
            _manifest(
                run_id="b", repos=repos, base_url=None,
                automation=dict(invalid)),
            [finding_factory(repo="r1", confidence=0.9)],
        ),
        truth,
        calibration,
    )

    assert result["claim_status"] == "unfair_comparison"
    assert result["audit"]["refusal"]["fairness_fields"][
        "automation_budget"
    ]["status"] == "missing"


def test_malformed_automation_section_cannot_fall_back_to_endpoint_mode(
    finding_factory,
):
    repos = ["r1"]
    truth = _truth(repos)
    calibration = freeze_calibration(
        _calibration(), source_run="calib-dev-1", source_split="dev")
    malformed = {"budget": {"max_requests": 20}}

    result = benchmark_quality(
        BenchmarkArm(
            "a",
            _manifest(run_id="a", repos=repos, automation=dict(malformed)),
            [finding_factory(repo="r1", confidence=0.9)],
        ),
        BenchmarkArm(
            "b",
            _manifest(run_id="b", repos=repos, automation=dict(malformed)),
            [finding_factory(repo="r1", confidence=0.9)],
        ),
        truth,
        calibration,
    )

    assert result["audit"]["mode"] == "automation"
    assert result["claim_status"] == "unfair_comparison"
    assert "automation_fingerprint" in result["audit"]["refusal"][
        "fairness_fields"
    ]


def test_tampered_live_claim_cannot_reuse_a_mock_fingerprint(
    finding_factory,
):
    repos = ["r1"]
    truth = _truth(repos)
    calibration = freeze_calibration(
        _calibration(), source_run="calib-dev-1", source_split="dev")
    tampered = _automation(provider_mode="mock")
    tampered["provider_mode"] = "live"
    tampered["claim_level"] = "live-provider-evidence"

    result = benchmark_quality(
        BenchmarkArm(
            "a",
            _manifest(
                run_id="a", split="test", repos=repos,
                base_url=None, automation=dict(tampered)),
            [finding_factory(repo="r1", confidence=0.9)],
        ),
        BenchmarkArm(
            "b",
            _manifest(
                run_id="b", split="test", repos=repos,
                base_url=None, automation=dict(tampered)),
            [finding_factory(repo="r1", confidence=0.9)],
        ),
        truth,
        calibration,
    )

    assert result["claim_status"] == "unfair_comparison"
    assert result["audit"]["refusal"]["fairness_fields"][
        "automation_fingerprint_payload_a"
    ]["status"] == "mismatch"


def test_incomplete_or_failed_task_execution_is_never_scored(
    finding_factory,
):
    repos = ["r1"]
    truth = _truth(repos)
    calibration = freeze_calibration(
        _calibration(), source_run="calib-dev-1", source_split="dev")
    manifest_b = _manifest(
        run_id="b", repos=repos, planned_tasks=3)
    manifest_b["execution"].update({
        "completed_tasks": 2,
        "successful_tasks": 1,
        "failed_tasks": 1,
        "missing_tasks": 1,
        "error_counts": {"json_invalid": 1},
        "scan_completed": True,
    })

    result = benchmark_quality(
        BenchmarkArm(
            "a",
            _manifest(run_id="a", repos=repos, planned_tasks=3),
            [finding_factory(repo="r1", confidence=0.9)],
        ),
        BenchmarkArm(
            "b",
            manifest_b,
            [finding_factory(repo="r1", confidence=0.9)],
        ),
        truth,
        calibration,
    )

    assert result["claim_status"] == "unfair_comparison"
    assert result["audit"]["refusal"]["fairness_fields"][
        "execution_complete_b"
    ]["status"] == "mismatch"


def test_single_run_execution_audit_rejects_non_sha_plan_bindings():
    manifest = _manifest(run_id="a", planned_tasks=3)
    manifest["task_plan_sha256"] = "not-a-sha"
    manifest["execution"]["planned_task_ids_sha256"] = "not-a-sha"
    manifest["execution"]["completed_task_ids_sha256"] = "not-a-sha"

    assert audit_execution(manifest)["status"] == "invalid"


def test_mock_automation_cannot_claim_on_test(
    finding_factory,
):
    repos = [f"r{i}" for i in range(40)]
    truth = _truth(repos, positive_repos=repos)
    calibration = freeze_calibration(
        _calibration(), source_run="calib-dev-1", source_split="dev")
    mock = _automation(
        provider_mode="mock",
        budget={
            "global_calls": 200,
            "global_tokens": 2_000_000,
            "per_arm_calls": 100,
            "per_arm_tokens": 1_000_000,
        })

    result = benchmark_quality(
        BenchmarkArm(
            "baseline",
            _manifest(
                run_id="a", split="test", repos=repos, base_url=None,
                automation=dict(mock)),
            [finding_factory(repo=repo, confidence=0.9)
             for repo in repos[:10]],
        ),
        BenchmarkArm(
            "quality",
            _manifest(
                run_id="b", split="test", repos=repos, base_url=None,
                automation=dict(mock)),
            [finding_factory(repo=repo, confidence=0.9) for repo in repos],
        ),
        truth,
        calibration,
    )

    assert result["claim_status"] == "unfair_comparison"
    assert result["audit"]["evidence"]["live_provider_mode_a"][
        "status"
    ] == "mismatch"
    assert result["audit"]["evidence"]["claim_level_b"]["status"] == "mismatch"


def test_mock_automation_remains_valid_for_dev_exploration(finding_factory):
    repos = ["r1", "r2"]
    truth = _truth(repos)
    calibration = freeze_calibration(
        _calibration(), source_run="calib-dev-1", source_split="dev")
    mock = _automation(provider_mode="mock")

    result = benchmark_quality(
        BenchmarkArm(
            "baseline",
            _manifest(
                run_id="a", repos=repos, base_url=None,
                automation=dict(mock)),
            [finding_factory(repo="r1", confidence=0.9)],
        ),
        BenchmarkArm(
            "quality",
            _manifest(
                run_id="b", repos=repos, base_url=None,
                automation=dict(mock)),
            [finding_factory(repo="r1", confidence=0.9)],
        ),
        truth,
        calibration,
    )

    assert result["audit"]["comparable"] is True
    assert result["claim_status"] == "exploratory"


def test_test_split_refuses_non_dev_calibration_source(finding_factory):
    repos = ["r1"]
    truth = _truth(repos)
    calibration = freeze_calibration(_calibration(), source_run="calib-train-1",
                                     source_split="train_syn")

    result = benchmark_quality(
        BenchmarkArm("a", _manifest(run_id="a", split="test", repos=repos),
                     [finding_factory(repo="r1", confidence=0.9)]),
        BenchmarkArm("b", _manifest(run_id="b", split="test", repos=repos),
                     []),
        truth,
        calibration,
    )

    assert result["claim_status"] == "unfair_comparison"
    assert result["audit"]["refusal"]["evidence_fields"]["calibration_source_split"]["status"] == "mismatch"


def test_test_split_refuses_calibration_sha_mismatch(finding_factory):
    repos = ["r1"]
    truth = _truth(repos)
    calibration = freeze_calibration(_calibration(), source_run="calib-dev-1",
                                     source_split="dev", sha256="0" * 64)

    result = benchmark_quality(
        BenchmarkArm("a", _manifest(run_id="a", split="test", repos=repos),
                     [finding_factory(repo="r1", confidence=0.9)]),
        BenchmarkArm("b", _manifest(run_id="b", split="test", repos=repos),
                     []),
        truth,
        calibration,
    )

    assert result["claim_status"] == "unfair_comparison"
    assert result["audit"]["refusal"]["evidence_fields"]["calibration_sha256"]["status"] == "mismatch"


def test_missing_calibration_sha_is_not_silently_reconstructed(finding_factory):
    repos = ["r1"]
    truth = _truth(repos)
    calibration = freeze_calibration(
        _calibration(),
        source_run="calib-dev-1",
        source_split="dev",
        sha256="",
    )

    result = benchmark_quality(
        BenchmarkArm(
            "a",
            _manifest(run_id="a", split="test", repos=repos),
            [finding_factory(repo="r1", confidence=0.9)],
        ),
        BenchmarkArm(
            "b",
            _manifest(run_id="b", split="test", repos=repos),
            [],
        ),
        truth,
        calibration,
    )

    assert result["claim_status"] == "unfair_comparison"
    assert result["audit"]["refusal"]["evidence_fields"][
        "calibration_sha256"
    ]["status"] == "missing"


def test_test_split_claim_status_surpasses_only_after_all_guards(finding_factory):
    repos = [f"r{i}" for i in range(40)]
    truth = _truth(repos, positive_repos=repos)
    calibration = freeze_calibration(_calibration(), source_run="calib-dev-1",
                                     source_split="dev")
    automation = _automation()

    arm_a = BenchmarkArm(
        "a",
        _manifest(
            run_id="a", split="test", repos=repos, automation=automation),
        [finding_factory(repo=repo, confidence=0.9) for repo in repos[:10]],
    )
    arm_b = BenchmarkArm(
        "b",
        _manifest(
            run_id="b", split="test", repos=repos, automation=automation),
        [finding_factory(repo=repo, confidence=0.9) for repo in repos],
    )

    result = benchmark_quality(arm_a, arm_b, truth, calibration)

    assert result["claim_status"] == "surpasses"
    assert result["comparison"]["mcnemar"]["c"] == 30
    assert result["comparison"]["mcnemar"]["p_value"] < 0.05
    assert all(
        result["claim_guardrails"][name]["pass"]
        for name in ("discordant", "mcnemar", "macro_f1", "precision",
                     "false_positives")
    )


def test_test_split_without_automation_evidence_is_refused(finding_factory):
    repos = [f"r{i}" for i in range(40)]
    truth = _truth(repos, positive_repos=repos)
    calibration = freeze_calibration(
        _calibration(), source_run="calib-dev-1", source_split="dev")

    result = benchmark_quality(
        BenchmarkArm(
            "a",
            _manifest(run_id="a", split="test", repos=repos),
            [finding_factory(repo=repo, confidence=0.9) for repo in repos[:10]],
        ),
        BenchmarkArm(
            "b",
            _manifest(run_id="b", split="test", repos=repos),
            [finding_factory(repo=repo, confidence=0.9) for repo in repos],
        ),
        truth,
        calibration,
    )

    assert result["claim_status"] == "unfair_comparison"
    assert result["audit"]["refusal"]["evidence_fields"][
        "test_automation_evidence"
    ]["status"] == "missing"


def test_test_split_is_underpowered_below_25_discordant(finding_factory):
    repos = [f"r{i}" for i in range(6)]
    truth = _truth(repos, positive_repos=repos)
    calibration = freeze_calibration(
        _calibration(), source_run="calib-dev-1", source_split="dev")

    result = benchmark_quality(
        BenchmarkArm(
            "baseline",
            _manifest(
                run_id="a", split="test", repos=repos,
                automation=_automation()),
            [],
        ),
        BenchmarkArm(
            "quality",
            _manifest(
                run_id="b", split="test", repos=repos,
                automation=_automation()),
            [finding_factory(repo=repo, confidence=0.9) for repo in repos],
        ),
        truth,
        calibration,
    )

    assert result["claim_status"] == "underpowered"
    assert result["claim_guardrails"]["discordant"]["actual"] == 6


def test_test_split_is_inferior_when_significance_favors_baseline(finding_factory):
    repos = [f"r{i}" for i in range(40)]
    truth = _truth(repos, positive_repos=repos)
    calibration = freeze_calibration(
        _calibration(), source_run="calib-dev-1", source_split="dev")

    result = benchmark_quality(
        BenchmarkArm(
            "baseline",
            _manifest(
                run_id="a", split="test", repos=repos,
                automation=_automation()),
            [finding_factory(repo=repo, confidence=0.9) for repo in repos],
        ),
        BenchmarkArm(
            "quality",
            _manifest(
                run_id="b", split="test", repos=repos,
                automation=_automation()),
            [finding_factory(repo=repo, confidence=0.9) for repo in repos[:10]],
        ),
        truth,
        calibration,
    )

    assert result["claim_status"] == "inferior"
    assert result["claim_guardrails"]["mcnemar"]["favors_quality"] is False


def test_test_split_is_inconclusive_without_significance(finding_factory):
    repos = [f"r{i}" for i in range(30)]
    truth = _truth(repos, positive_repos=repos)
    calibration = freeze_calibration(
        _calibration(), source_run="calib-dev-1", source_split="dev")

    result = benchmark_quality(
        BenchmarkArm(
            "baseline",
            _manifest(
                run_id="a", split="test", repos=repos,
                automation=_automation()),
            [finding_factory(repo=repo, confidence=0.9) for repo in repos[:15]],
        ),
        BenchmarkArm(
            "quality",
            _manifest(
                run_id="b", split="test", repos=repos,
                automation=_automation()),
            [finding_factory(repo=repo, confidence=0.9) for repo in repos[15:]],
        ),
        truth,
        calibration,
    )

    assert result["claim_status"] == "inconclusive"
    assert result["claim_guardrails"]["discordant"]["pass"] is True
    assert result["claim_guardrails"]["mcnemar"]["significant"] is False


def test_macro_f1_regression_is_inferior_even_without_significance(
    finding_factory,
):
    repos = [f"r{i}" for i in range(40)]
    truth = _truth(repos, positive_repos=repos)
    calibration = freeze_calibration(
        _calibration(), source_run="calib-dev-1", source_split="dev")

    result = benchmark_quality(
        BenchmarkArm(
            "baseline",
            _manifest(
                run_id="a", split="test", repos=repos,
                automation=_automation()),
            [finding_factory(repo=repo, confidence=0.9)
             for repo in repos[:20]],
        ),
        BenchmarkArm(
            "quality",
            _manifest(
                run_id="b", split="test", repos=repos,
                automation=_automation()),
            [finding_factory(repo=repo, confidence=0.9)
             for repo in repos[25:]],
        ),
        truth,
        calibration,
    )

    assert result["claim_guardrails"]["discordant"]["pass"] is True
    assert result["claim_guardrails"]["mcnemar"]["significant"] is False
    assert result["claim_guardrails"]["macro_f1"]["pass"] is False
    assert result["claim_status"] == "inferior"


def test_precision_guard_blocks_claim_even_when_pair_test_favors_quality(
    finding_factory,
):
    positives = [f"p{i}" for i in range(40)]
    negatives = [f"n{i}" for i in range(20)]
    repos = positives + negatives
    truth = _truth(repos, positive_repos=positives)
    calibration = freeze_calibration(
        _calibration(), source_run="calib-dev-1", source_split="dev")

    result = benchmark_quality(
        BenchmarkArm(
            "baseline",
            _manifest(
                run_id="a", split="test", repos=repos,
                automation=_automation()),
            [finding_factory(repo=repo, confidence=0.9) for repo in positives[:10]],
        ),
        BenchmarkArm(
            "quality",
            _manifest(
                run_id="b", split="test", repos=repos,
                automation=_automation()),
            [finding_factory(repo=repo, confidence=0.9)
             for repo in positives + negatives[:5]],
        ),
        truth,
        calibration,
    )

    assert result["claim_status"] == "inconclusive"
    assert result["claim_guardrails"]["mcnemar"]["pass"] is True
    assert result["claim_guardrails"]["macro_f1"]["pass"] is True
    assert result["claim_guardrails"]["precision"]["pass"] is False
    assert result["claim_guardrails"]["false_positives"]["exception_applied"] is True
