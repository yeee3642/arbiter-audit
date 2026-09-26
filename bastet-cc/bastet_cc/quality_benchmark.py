"""Fair, paired quality benchmarking for two Bastet arms.

This module is intentionally pure: the caller supplies already-loaded manifests,
findings, truth rows, and one frozen calibration artefact. That keeps the core
benchmark testable in isolation and lets a CLI wire file I/O around it without
putting policy inside the command layer.

Two constraints dominate the design.

1. The arms must be comparable *before* scoring. A quality comparison is refused
   when the manifests cannot prove the same model/base URL, or the same
   automation profile fingerprint/budget/subject, plus the same repos and split.
2. TEST may only be scored with one shared calibration artefact frozen on DEV and
   recorded by SHA-256. Missing or mismatched evidence is an explicit refusal, not
   a silent fallback to fitting each arm separately.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

import pandas as pd

from .aggregate import Calibration, aggregate, confusion_by_tag, macro_f1, scoreable_tags, truth_map
from .automation.contracts import AIS3_BASE_URL, AIS3_PINNED_MODEL
from .evaluate import Confusion
from .findings import Finding
from .hermes import HERMES_VERSION
from .stats import describe_paired, mcnemar
from .twincourt import (
    OVERLAY_SCHEMA_VERSION,
    TWINCOURT_PROMPT_VERSION,
    TWINCOURT_SCHEMA_VERSION,
    TWINCOURT_TREATMENT,
    TWINCOURT_VERSION,
)

CLAIM_ALPHA = 0.05
MIN_DISCORDANT_FOR_NO_DIFFERENCE = 25
PRECISION_TOLERANCE = 0.02
MAX_FP_INCREASE = 0.10
_EXPECTED_QUALITY_VERSIONS = {
    "hermes": HERMES_VERSION,
    "twincourt": TWINCOURT_VERSION,
    "twincourt_prompt": TWINCOURT_PROMPT_VERSION,
    "twincourt_schema": TWINCOURT_SCHEMA_VERSION,
    "overlay_schema": OVERLAY_SCHEMA_VERSION,
}
_AUTOMATION_FINGERPRINT_FIELDS = (
    "experiment_id",
    "subject_id",
    "endpoint",
    "model",
    "provider_mode",
    "selected_workflow",
    "workflow_sha256",
    "prompt_sha256",
    "profile_version",
    "adapter_version",
    "schema_version",
    "budget",
    "claim_level",
)


@dataclass(frozen=True)
class BenchmarkArm:
    """One scored arm, already loaded by the caller."""

    label: str
    manifest: Mapping[str, Any]
    findings: Sequence[Finding]
    cost: Mapping[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class CalibrationArtifact:
    """One frozen calibration shared by both arms."""

    calibration: Calibration
    sha256: str
    source_run: str
    source_split: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "sha256": self.sha256,
            "source_run": self.source_run,
            "source_split": self.source_split,
            "calibration": self.calibration.to_dict(),
        }


def calibration_sha256(calibration: Calibration) -> str:
    blob = json.dumps(calibration.to_dict(), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def freeze_calibration(calibration: Calibration, *, source_run: str,
                       source_split: str, sha256: str | None = None
                       ) -> CalibrationArtifact:
    return CalibrationArtifact(
        calibration=calibration,
        sha256=(
            calibration_sha256(calibration)
            if sha256 is None
            else str(sha256).strip()
        ),
        source_run=str(source_run).strip(),
        source_split=str(source_split).strip().lower(),
    )


def benchmark_quality(arm_a: BenchmarkArm, arm_b: BenchmarkArm, truth_df: pd.DataFrame,
                      calibration: CalibrationArtifact) -> dict[str, Any]:
    """Audit two arms, then score them with one shared calibration artefact."""

    audit = audit_quality_inputs(arm_a, arm_b, calibration)
    if not audit["comparable"]:
        return {
            "audit": audit,
            "arms": None,
            "comparison": None,
            "claim_status": "unfair_comparison",
            "claim_guardrails": None,
        }

    repos = list(audit["normalized"]["repos"])
    split = audit["normalized"]["split"]
    truth = truth_map(truth_df, repos)
    tags = scoreable_tags(truth, repos)
    if not tags:
        refusal = {
            "status": "missing",
            "required": True,
            "a": [],
            "b": [],
            "message": "truth rows contain no scoreable positive tags for the audited repositories",
        }
        audit["evidence"]["scoreable_tags"] = refusal
        audit["refusal"]["evidence_fields"]["scoreable_tags"] = refusal
        audit["refusal"]["reasons"].append("scoreable_tags: truth rows contain no scoreable positive tags")
        audit["comparable"] = False
        return {
            "audit": audit,
            "arms": None,
            "comparison": None,
            "claim_status": "unfair_comparison",
            "claim_guardrails": None,
        }

    preds_a, metrics_a = _score_arm(arm_a, calibration.calibration, truth, repos, tags)
    preds_b, metrics_b = _score_arm(arm_b, calibration.calibration, truth, repos, tags)
    comparison = _paired_metrics(arm_a.label, arm_b.label, preds_a, preds_b, truth, repos, tags)
    comparison["cost"] = _compare_costs(metrics_a["cost"], metrics_b["cost"])
    claim_status, claim_guardrails = _claim_status(
        split, comparison["mcnemar"], metrics_a, metrics_b)

    return {
        "audit": audit,
        "arms": {
            "a": metrics_a,
            "b": metrics_b,
        },
        "comparison": comparison,
        "claim_status": claim_status,
        "claim_guardrails": claim_guardrails,
        "guardrails": {
            "alpha": CLAIM_ALPHA,
            "min_discordant": MIN_DISCORDANT_FOR_NO_DIFFERENCE,
            "precision_tolerance": PRECISION_TOLERANCE,
            "max_false_positive_increase": MAX_FP_INCREASE,
            "test_requires_dev_calibration": True,
            "shared_calibration_only": True,
        },
    }


def audit_quality_inputs(arm_a: BenchmarkArm, arm_b: BenchmarkArm,
                         calibration: CalibrationArtifact) -> dict[str, Any]:
    """Audit fairness and evidentiary preconditions before any scoring."""

    man_a = dict(arm_a.manifest)
    man_b = dict(arm_b.manifest)

    normalized = {
        "model_a": _manifest_model(man_a),
        "model_b": _manifest_model(man_b),
        "base_url_a": _manifest_base_url(man_a),
        "base_url_b": _manifest_base_url(man_b),
        "repos_a": _manifest_repos(man_a),
        "repos_b": _manifest_repos(man_b),
        "split_a": _manifest_split(man_a),
        "split_b": _manifest_split(man_b),
        "splits_sha_a": _manifest_splits_sha(man_a),
        "splits_sha_b": _manifest_splits_sha(man_b),
        "automation_fingerprint_a": _automation_field(man_a, "fingerprint"),
        "automation_fingerprint_b": _automation_field(man_b, "fingerprint"),
        "automation_budget_a": _automation_budget(man_a),
        "automation_budget_b": _automation_budget(man_b),
        "automation_subject_a": _automation_subject(man_a),
        "automation_subject_b": _automation_subject(man_b),
        "automation_endpoint_a": _automation_field(man_a, "endpoint"),
        "automation_endpoint_b": _automation_field(man_b, "endpoint"),
        "automation_provider_mode_a": _automation_field(man_a, "provider_mode"),
        "automation_provider_mode_b": _automation_field(man_b, "provider_mode"),
        "automation_claim_level_a": _automation_field(man_a, "claim_level"),
        "automation_claim_level_b": _automation_field(man_b, "claim_level"),
        "provider_fingerprint_a": _provider_fingerprint(man_a),
        "provider_fingerprint_b": _provider_fingerprint(man_b),
        "quality_budget_a": man_a.get("quality_budget_chars"),
        "quality_budget_b": man_b.get("quality_budget_chars"),
        "task_plan_sha_a": _clean_text(man_a.get("task_plan_sha256")),
        "task_plan_sha_b": _clean_text(man_b.get("task_plan_sha256")),
    }
    # Mode is selected from raw manifest intent, not from successfully parsed
    # fields. Otherwise a present-but-malformed automation section normalizes
    # to all-None and silently falls through to the less strict endpoint audit.
    automation_declared = (
        man_a.get("automation") is not None
        or man_b.get("automation") is not None
    )
    audit_mode = "automation" if automation_declared else "endpoint"

    fairness = {
        "model": _eq_check(normalized["model_a"], normalized["model_b"]),
        "repos": _eq_check(normalized["repos_a"], normalized["repos_b"]),
        "split": _eq_check(normalized["split_a"], normalized["split_b"]),
        "splits_sha256": _eq_check(normalized["splits_sha_a"], normalized["splits_sha_b"]),
        "provider_profile_fingerprint": _eq_check(
            normalized["provider_fingerprint_a"],
            normalized["provider_fingerprint_b"],
        ),
        "provider_profile_fingerprint_format_a": _sha256_check(
            normalized["provider_fingerprint_a"],
            "arm A provider profile fingerprint must be SHA-256",
        ),
        "provider_profile_fingerprint_format_b": _sha256_check(
            normalized["provider_fingerprint_b"],
            "arm B provider profile fingerprint must be SHA-256",
        ),
        "quality_budget_chars": _positive_int_eq_check(
            normalized["quality_budget_a"], normalized["quality_budget_b"]),
        "quality_treatment_roles": _role_check(
            man_a, man_b, "quality_treatment", "none", TWINCOURT_TREATMENT),
        "quality_versions": _role_check(
            man_a, man_b, "quality_versions", None, _EXPECTED_QUALITY_VERSIONS),
        "scan_arm": _role_check(
            man_a, man_b, "arm", "routed", "routed"),
        "verification_enabled": _role_check(
            man_a, man_b, "verify", True, True),
        "closure_disabled": _role_check(
            man_a, man_b, "closure", False, False),
        "detection_prompt_version": _eq_check(
            man_a.get("prompt_version"), man_b.get("prompt_version")),
        "detector_count": _eq_check(
            man_a.get("detectors"), man_b.get("detectors")),
        "planned_tasks": _positive_int_eq_check(
            man_a.get("planned_tasks"), man_b.get("planned_tasks")),
        "task_plan_sha256": _eq_check(
            normalized["task_plan_sha_a"], normalized["task_plan_sha_b"]),
        "task_plan_sha256_format_a": _sha256_check(
            normalized["task_plan_sha_a"],
            "arm A task plan hash must be SHA-256",
        ),
        "task_plan_sha256_format_b": _sha256_check(
            normalized["task_plan_sha_b"],
            "arm B task plan hash must be SHA-256",
        ),
        "execution_complete_a": _execution_check(man_a),
        "execution_complete_b": _execution_check(man_b),
    }
    if audit_mode == "automation":
        fairness["automation_fingerprint"] = _eq_check(
            normalized["automation_fingerprint_a"], normalized["automation_fingerprint_b"])
        fairness["automation_budget"] = _eq_check(
            normalized["automation_budget_a"], normalized["automation_budget_b"])
        fairness["automation_subject"] = _eq_check(
            normalized["automation_subject_a"], normalized["automation_subject_b"])
        fairness["automation_endpoint"] = _eq_check(
            normalized["automation_endpoint_a"], normalized["automation_endpoint_b"])
        fairness["automation_provider_mode"] = _eq_check(
            normalized["automation_provider_mode_a"],
            normalized["automation_provider_mode_b"],
        )
        fairness["automation_claim_level"] = _eq_check(
            normalized["automation_claim_level_a"],
            normalized["automation_claim_level_b"],
        )
        fairness["automation_profile_binding_a"] = _value_check(
            normalized["automation_fingerprint_a"],
            normalized["provider_fingerprint_a"],
            "arm A automation fingerprint must match provider_profile",
        )
        fairness["automation_profile_binding_b"] = _value_check(
            normalized["automation_fingerprint_b"],
            normalized["provider_fingerprint_b"],
            "arm B automation fingerprint must match provider_profile",
        )
        fairness["automation_fingerprint_payload_a"] = (
            _automation_fingerprint_check(man_a))
        fairness["automation_fingerprint_payload_b"] = (
            _automation_fingerprint_check(man_b))
        fairness["automation_claim_binding_a"] = (
            _automation_claim_binding_check(man_a))
        fairness["automation_claim_binding_b"] = (
            _automation_claim_binding_check(man_b))
        fairness["automation_model_binding_a"] = _value_check(
            _automation_field(man_a, "model"),
            normalized["model_a"],
            "arm A automation model must match its run manifest",
        )
        fairness["automation_model_binding_b"] = _value_check(
            _automation_field(man_b, "model"),
            normalized["model_b"],
            "arm B automation model must match its run manifest",
        )
        fairness["automation_pinned_model_a"] = _value_check(
            _automation_field(man_a, "model"),
            AIS3_PINNED_MODEL,
            "arm A automation model is not the pinned AIS3 model",
        )
        fairness["automation_pinned_model_b"] = _value_check(
            _automation_field(man_b, "model"),
            AIS3_PINNED_MODEL,
            "arm B automation model is not the pinned AIS3 model",
        )
        fairness["automation_pinned_endpoint_a"] = _value_check(
            normalized["automation_endpoint_a"],
            AIS3_BASE_URL,
            "arm A automation endpoint is not the pinned AIS3 endpoint",
        )
        fairness["automation_pinned_endpoint_b"] = _value_check(
            normalized["automation_endpoint_b"],
            AIS3_BASE_URL,
            "arm B automation endpoint is not the pinned AIS3 endpoint",
        )
        fairness["automation_evidence_complete_a"] = _value_check(
            _automation_section(man_a).get("evidence_complete"),
            True,
            "arm A automation evidence must be complete",
        )
        fairness["automation_evidence_complete_b"] = _value_check(
            _automation_section(man_b).get("evidence_complete"),
            True,
            "arm B automation evidence must be complete",
        )
    else:
        fairness["base_url"] = _eq_check(normalized["base_url_a"], normalized["base_url_b"])

    split = normalized["split_a"] if fairness["split"]["status"] == "ok" else None
    evidence = _calibration_checks(calibration, split)
    if split == "test" and audit_mode != "automation":
        evidence["test_automation_evidence"] = {
            "status": "missing",
            "required": True,
            "a": man_a.get("automation"),
            "b": man_b.get("automation"),
            "message": (
                "claim-bearing TEST requires complete live automation "
                "evidence for both arms"
            ),
        }
    if audit_mode == "automation" and split == "test":
        evidence["live_provider_mode_a"] = _value_check(
            normalized["automation_provider_mode_a"],
            "live",
            "claim-bearing TEST requires live provider evidence for arm A",
        )
        evidence["live_provider_mode_b"] = _value_check(
            normalized["automation_provider_mode_b"],
            "live",
            "claim-bearing TEST requires live provider evidence for arm B",
        )
        evidence["claim_level_a"] = _value_check(
            normalized["automation_claim_level_a"],
            "live-provider-evidence",
            "arm A gateway manifest is not claim-eligible provider evidence",
        )
        evidence["claim_level_b"] = _value_check(
            normalized["automation_claim_level_b"],
            "live-provider-evidence",
            "arm B gateway manifest is not claim-eligible provider evidence",
        )

    refusal_fairness = {k: v for k, v in fairness.items() if v["status"] != "ok"}
    refusal_evidence = {k: v for k, v in evidence.items() if v["status"] != "ok"}
    reasons = ([f"{name}: {row['message']}" for name, row in refusal_fairness.items()]
               + [f"{name}: {row['message']}" for name, row in refusal_evidence.items()])

    comparable = not refusal_fairness and not refusal_evidence
    return {
        "mode": audit_mode,
        "comparable": comparable,
        "fairness": fairness,
        "evidence": evidence,
        "refusal": {
            "fairness_fields": refusal_fairness,
            "evidence_fields": refusal_evidence,
            "reasons": reasons,
        },
        "normalized": {
            "repos": list(normalized["repos_a"] or ()),
            "split": split,
            "model": normalized["model_a"],
            "base_url": normalized["base_url_a"],
            "splits_sha256": normalized["splits_sha_a"],
        },
    }


def audit_execution(manifest: Mapping[str, Any]) -> dict[str, Any]:
    """Public single-run completeness gate used before DEV calibration."""
    return _execution_check(manifest)


def _calibration_checks(calibration: CalibrationArtifact, split: str | None) -> dict[str, dict[str, Any]]:
    payload_sha = calibration_sha256(calibration.calibration)
    out = {
        "shared_calibration": _value_check(bool(calibration.calibration), True, "one shared calibration artifact is required"),
        "calibration_sha256": _value_check(
            calibration.sha256 or None,
            payload_sha,
            "calibration SHA-256 must be recorded and match the payload",
        ),
        "calibration_source_run": _value_check(
            calibration.source_run or None,
            calibration.source_run or None,
            "calibration source run must be recorded",
        ),
    }
    if split == "test":
        out["calibration_source_split"] = _value_check(
            calibration.source_split or None,
            "dev",
            "TEST requires a calibration frozen on DEV",
        )
    else:
        out["calibration_source_split"] = _value_check(
            calibration.source_split or None,
            calibration.source_split or None,
            "calibration source split must be recorded",
        )
    return out


def _score_arm(arm: BenchmarkArm, calibration: Calibration, truth: dict[str, set[str]],
               repos: Sequence[str], tags: Sequence[str]
               ) -> tuple[dict[str, dict[str, bool]], dict[str, Any]]:
    preds = aggregate(arm.findings, calibration, repos=repos, tags=tags)
    confusions = confusion_by_tag(preds, truth, repos, tags)
    pooled = _pooled_confusion(confusions)
    return preds, {
        "label": arm.label,
        "manifest": {
            "run_id": arm.manifest.get("run_id"),
            "arm": arm.manifest.get("arm") or arm.manifest.get("mode"),
        },
        "quality": {
            "macro_f1": macro_f1(confusions),
            "pooled": pooled.to_dict(),
            "per_tag": {tag: cm.to_dict() for tag, cm in confusions.items()},
            "n_repos": len(repos),
            "n_tags": len(tags),
        },
        "findings": _finding_metrics(arm.findings),
        "verdicts": _verdict_metrics(arm.findings),
        "cost": _cost_metrics(arm),
    }


def _paired_metrics(label_a: str, label_b: str,
                    preds_a: dict[str, dict[str, bool]],
                    preds_b: dict[str, dict[str, bool]],
                    truth: dict[str, set[str]], repos: Sequence[str],
                    tags: Sequence[str]) -> dict[str, Any]:
    pairs: list[tuple[bool, bool]] = []
    per_repo_a: list[float] = []
    per_repo_b: list[float] = []
    both_right = both_wrong = only_a = only_b = 0

    for repo in repos:
        repo_cm_a = confusion_by_tag(
            {tag: {repo: preds_a[tag].get(repo, False)} for tag in tags},
            truth, [repo], tags)
        repo_cm_b = confusion_by_tag(
            {tag: {repo: preds_b[tag].get(repo, False)} for tag in tags},
            truth, [repo], tags)
        per_repo_a.append(macro_f1(repo_cm_a))
        per_repo_b.append(macro_f1(repo_cm_b))

        for tag in tags:
            actual = tag in truth.get(repo, set())
            a_ok = preds_a[tag].get(repo, False) == actual
            b_ok = preds_b[tag].get(repo, False) == actual
            pairs.append((a_ok, b_ok))
            if a_ok and b_ok:
                both_right += 1
            elif not a_ok and not b_ok:
                both_wrong += 1
            elif a_ok:
                only_a += 1
            else:
                only_b += 1

    pair_stats = mcnemar(pairs)
    return {
        "decision_pairs": {
            "n": len(pairs),
            "both_right": both_right,
            "both_wrong": both_wrong,
            "only_a": only_a,
            "only_b": only_b,
            "labels": {"a": label_a, "b": label_b},
        },
        "mcnemar": pair_stats.to_dict(),
        "paired_macro_f1": describe_paired(per_repo_a, per_repo_b,
                                            label_a=label_a, label_b=label_b),
    }


def _claim_status(
    split: str | None,
    mcnemar_result: Mapping[str, Any],
    metrics_a: Mapping[str, Any],
    metrics_b: Mapping[str, Any],
) -> tuple[str, dict[str, Any]]:
    """Apply the frozen quality claim gate; arm B is the quality treatment."""
    b = int(mcnemar_result.get("b") or 0)  # only baseline is correct
    c = int(mcnemar_result.get("c") or 0)  # only quality is correct
    p_value = float(mcnemar_result.get("p_value") or 1.0)
    discordant = int(mcnemar_result.get("discordant") or 0)

    quality_a = metrics_a["quality"]
    quality_b = metrics_b["quality"]
    macro_a = float(quality_a["macro_f1"])
    macro_b = float(quality_b["macro_f1"])
    pooled_a = quality_a["pooled"]
    pooled_b = quality_b["pooled"]
    precision_a = pooled_a.get("precision")
    precision_b = pooled_b.get("precision")
    fp_a = int(pooled_a.get("fp") or 0)
    fp_b = int(pooled_b.get("fp") or 0)

    significant = p_value < CLAIM_ALPHA
    favors_quality = c > b
    macro_not_lower = macro_b + 1e-12 >= macro_a
    macro_improved = macro_b > macro_a + 1e-12
    precision_ok = (
        precision_a is not None
        and precision_b is not None
        and float(precision_b) + PRECISION_TOLERANCE + 1e-12
        >= float(precision_a)
    )
    fp_limit = fp_a * (1.0 + MAX_FP_INCREASE)
    fp_within_limit = fp_b <= fp_limit + 1e-12
    fp_exception = macro_improved and significant and favors_quality
    fp_ok = fp_within_limit or fp_exception

    guardrails = {
        "split_is_test": split == "test",
        "discordant": {
            "actual": discordant,
            "minimum": MIN_DISCORDANT_FOR_NO_DIFFERENCE,
            "pass": discordant >= MIN_DISCORDANT_FOR_NO_DIFFERENCE,
        },
        "mcnemar": {
            "p_value": p_value,
            "alpha": CLAIM_ALPHA,
            "only_baseline_correct": b,
            "only_quality_correct": c,
            "significant": significant,
            "favors_quality": favors_quality,
            "pass": significant and favors_quality,
        },
        "macro_f1": {
            "baseline": macro_a,
            "quality": macro_b,
            "pass": macro_not_lower,
        },
        "precision": {
            "baseline": precision_a,
            "quality": precision_b,
            "max_absolute_drop": PRECISION_TOLERANCE,
            "pass": precision_ok,
        },
        "false_positives": {
            "baseline": fp_a,
            "quality": fp_b,
            "max_increase": MAX_FP_INCREASE,
            "within_limit": fp_within_limit,
            "exception_applied": fp_exception and not fp_within_limit,
            "pass": fp_ok,
        },
    }

    if split != "test":
        return "exploratory", guardrails
    if not macro_not_lower:
        return "inferior", guardrails
    if discordant < MIN_DISCORDANT_FOR_NO_DIFFERENCE:
        return "underpowered", guardrails
    if not significant:
        return "inconclusive", guardrails
    if not favors_quality:
        return "inferior", guardrails
    if precision_ok and fp_ok:
        return "surpasses", guardrails
    return "inconclusive", guardrails


def _finding_metrics(findings: Sequence[Finding]) -> dict[str, Any]:
    confidences = [f.confidence for f in findings]
    return {
        "n_findings": len(findings),
        "n_repos": len({f.repo for f in findings if f.repo}),
        "n_tags": len({f.tag for f in findings if f.tag}),
        "n_detectors": len({f.detector_id for f in findings if f.detector_id}),
        "mean_confidence": (sum(confidences) / len(confidences)) if confidences else None,
    }


def _verdict_metrics(findings: Sequence[Finding]) -> dict[str, Any]:
    counts = Counter((f.verdict or "unverified") for f in findings)
    total = len(findings)
    verified = total - counts.get("unverified", 0)
    return {
        "counts": dict(sorted(counts.items())),
        "verified_share": (verified / total) if total else None,
    }


def _cost_metrics(arm: BenchmarkArm) -> dict[str, int]:
    out = {str(k): int(v) for k, v in dict(arm.cost).items()
           if isinstance(v, (int, float))}
    planned = arm.manifest.get("planned_tasks")
    if planned is not None and "planned_calls" not in out:
        out["planned_calls"] = int(planned)
    return dict(sorted(out.items()))


def _compare_costs(cost_a: Mapping[str, int], cost_b: Mapping[str, int]) -> dict[str, dict[str, int | None]]:
    keys = sorted(set(cost_a) | set(cost_b))
    out: dict[str, dict[str, int | None]] = {}
    for key in keys:
        a = cost_a.get(key)
        b = cost_b.get(key)
        out[key] = {
            "a": a,
            "b": b,
            "delta": (a - b) if a is not None and b is not None else None,
        }
    return out


def _pooled_confusion(confusions: Mapping[str, Confusion]) -> Confusion:
    pooled = Confusion()
    for cm in confusions.values():
        pooled.tp += cm.tp
        pooled.tn += cm.tn
        pooled.fp += cm.fp
        pooled.fn += cm.fn
    return pooled


def _manifest_model(manifest: Mapping[str, Any]) -> str | None:
    return _clean_text(manifest.get("model"))


def _manifest_base_url(manifest: Mapping[str, Any]) -> str | None:
    return _clean_text(manifest.get("base_url") or manifest.get("endpoint"))


def _manifest_repos(manifest: Mapping[str, Any]) -> tuple[str, ...] | None:
    raw = manifest.get("repos")
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
        return None
    return tuple(sorted({str(item).strip() for item in raw if str(item).strip()}))


def _manifest_split(manifest: Mapping[str, Any]) -> str | None:
    raw = manifest.get("split")
    if raw is None:
        raw = manifest.get("target")
    if raw is None:
        return None
    value = str(raw).strip().lower()
    return value if value else None


def _manifest_splits_sha(manifest: Mapping[str, Any]) -> str | None:
    return _clean_text(manifest.get("splits_sha256") or manifest.get("splits_hash"))


def _automation_section(manifest: Mapping[str, Any]) -> Mapping[str, Any]:
    raw = manifest.get("automation")
    return raw if isinstance(raw, Mapping) else {}


def _automation_field(manifest: Mapping[str, Any], name: str) -> str | None:
    return _clean_text(_automation_section(manifest).get(name))


def _automation_budget(manifest: Mapping[str, Any]) -> str | None:
    budget = _automation_section(manifest).get("budget")
    if not isinstance(budget, Mapping):
        return None
    from .automation.contracts import BudgetLimits
    expected = set(BudgetLimits.__dataclass_fields__)
    if set(budget) != expected or any(
        type(value) is not int or value <= 0 for value in budget.values()
    ):
        return None
    try:
        normalized = BudgetLimits(**dict(budget)).to_dict()
    except (TypeError, ValueError):
        return None
    return _canonical_json(normalized)


def _automation_subject(manifest: Mapping[str, Any]) -> str | None:
    automation = _automation_section(manifest)
    return _clean_text(automation.get("subject_id") or automation.get("subject"))


def _automation_fingerprint_check(
    manifest: Mapping[str, Any],
) -> dict[str, Any]:
    automation = manifest.get("automation")
    if not isinstance(automation, Mapping):
        return {
            "status": "missing",
            "required": True,
            "actual": None,
            "expected": None,
            "message": "automation fingerprint payload is missing",
        }
    missing = [
        field for field in _AUTOMATION_FINGERPRINT_FIELDS
        if automation.get(field) in (None, "")
    ]
    if missing:
        return {
            "status": "missing",
            "required": True,
            "actual": automation.get("fingerprint"),
            "expected": None,
            "message": (
                "automation fingerprint payload is missing "
                + ", ".join(missing)
            ),
        }
    payload = {
        field: automation[field]
        for field in _AUTOMATION_FINGERPRINT_FIELDS
    }
    expected = hashlib.sha256(
        _canonical_json(payload).encode("utf-8")).hexdigest()
    return _value_check(
        _clean_text(automation.get("fingerprint")),
        expected,
        "automation fingerprint must match its immutable payload",
    )


def _automation_claim_binding_check(
    manifest: Mapping[str, Any],
) -> dict[str, Any]:
    automation = _automation_section(manifest)
    mode = _clean_text(automation.get("provider_mode"))
    expected = {
        "mock": "pipeline-readiness-only",
        "live": "live-provider-evidence",
    }.get(mode or "")
    if expected is None:
        return {
            "status": "invalid",
            "required": True,
            "actual": mode,
            "expected": "mock or live",
            "message": "automation provider_mode is invalid",
        }
    return _value_check(
        _clean_text(automation.get("claim_level")),
        expected,
        "automation claim_level must match provider_mode",
    )


def _provider_fingerprint(manifest: Mapping[str, Any]) -> str | None:
    profile = manifest.get("provider_profile")
    if not isinstance(profile, Mapping):
        return None
    return _clean_text(profile.get("fingerprint"))


def _execution_check(manifest: Mapping[str, Any]) -> dict[str, Any]:
    execution = manifest.get("execution")
    if not isinstance(execution, Mapping):
        return {
            "status": "missing",
            "required": True,
            "actual": None,
            "expected": "complete successful execution",
            "message": "run execution summary is missing",
        }
    count_fields = (
        "planned_tasks",
        "completed_tasks",
        "successful_tasks",
        "failed_tasks",
        "missing_tasks",
        "unexpected_tasks",
        "invalid_result_rows",
    )
    if any(
        isinstance(execution.get(field), bool)
        or not isinstance(execution.get(field), int)
        or int(execution[field]) < 0
        for field in count_fields
    ):
        return {
            "status": "invalid",
            "required": True,
            "actual": dict(execution),
            "expected": "non-negative integer execution counts",
            "message": "run execution counts are invalid",
        }
    planned = manifest.get("planned_tasks")
    errors = execution.get("error_counts")
    plan_sha = _clean_text(manifest.get("task_plan_sha256"))
    recorded_plan_sha = _clean_text(
        execution.get("planned_task_ids_sha256"))
    completed_sha = _clean_text(
        execution.get("completed_task_ids_sha256"))
    hash_checks = (
        _sha256_check(plan_sha, "task plan hash must be SHA-256"),
        _sha256_check(
            recorded_plan_sha,
            "recorded planned-task hash must be SHA-256",
        ),
        _sha256_check(
            completed_sha,
            "completed-task hash must be SHA-256",
        ),
    )
    if any(check["status"] != "ok" for check in hash_checks):
        return {
            "status": "invalid",
            "required": True,
            "actual": dict(execution),
            "expected": "valid SHA-256 task-plan bindings",
            "message": "run execution task-plan hashes are invalid",
        }
    valid = (
        execution.get("scan_completed") is True
        and execution["planned_tasks"] == planned
        and execution["completed_tasks"] == planned
        and execution["successful_tasks"] == planned
        and execution["failed_tasks"] == 0
        and execution["missing_tasks"] == 0
        and execution["unexpected_tasks"] == 0
        and execution["invalid_result_rows"] == 0
        and isinstance(errors, Mapping)
        and not errors
        and recorded_plan_sha == plan_sha
        and completed_sha == plan_sha
    )
    if not valid:
        return {
            "status": "mismatch",
            "required": True,
            "actual": dict(execution),
            "expected": {
                "planned_tasks": planned,
                "successful_tasks": planned,
                "failed_tasks": 0,
                "missing_tasks": 0,
                "unexpected_tasks": 0,
                "invalid_result_rows": 0,
                "task_plan_sha256": plan_sha,
                "scan_completed": True,
            },
            "message": (
                "run must complete every planned task successfully "
                "without missing, failed, or unexpected results"
            ),
        }
    return {
        "status": "ok",
        "required": True,
        "actual": dict(execution),
        "expected": "complete successful execution",
        "message": "all planned tasks completed successfully",
    }


def _eq_check(a: Any, b: Any) -> dict[str, Any]:
    if a is None and b is None:
        return {
            "status": "missing",
            "required": True,
            "a": None,
            "b": None,
            "message": "missing in both manifests",
        }
    if a is None:
        return {
            "status": "missing",
            "required": True,
            "a": None,
            "b": b,
            "message": "missing in arm A manifest",
        }
    if b is None:
        return {
            "status": "missing",
            "required": True,
            "a": a,
            "b": None,
            "message": "missing in arm B manifest",
        }
    if a != b:
        return {
            "status": "mismatch",
            "required": True,
            "a": a,
            "b": b,
            "message": "arm manifests disagree",
        }
    return {
        "status": "ok",
        "required": True,
        "a": a,
        "b": b,
        "message": "matched",
    }


def _positive_int_eq_check(a: Any, b: Any) -> dict[str, Any]:
    row = _eq_check(a, b)
    if row["status"] != "ok":
        return row
    if isinstance(a, bool) or not isinstance(a, int) or a <= 0:
        return {
            "status": "invalid",
            "required": True,
            "a": a,
            "b": b,
            "message": "both manifests must declare the same positive integer",
        }
    return row


def _sha256_check(value: Any, message: str) -> dict[str, Any]:
    text = _clean_text(value)
    if text is None:
        return {
            "status": "missing",
            "required": True,
            "actual": None,
            "expected": "64 lowercase hexadecimal characters",
            "message": message,
        }
    if len(text) != 64 or any(char not in "0123456789abcdef" for char in text):
        return {
            "status": "invalid",
            "required": True,
            "actual": text,
            "expected": "64 lowercase hexadecimal characters",
            "message": message,
        }
    return {
        "status": "ok",
        "required": True,
        "actual": text,
        "expected": "64 lowercase hexadecimal characters",
        "message": "valid SHA-256",
    }


def _role_check(
    manifest_a: Mapping[str, Any],
    manifest_b: Mapping[str, Any],
    field: str,
    expected_a: Any,
    expected_b: Any,
) -> dict[str, Any]:
    present_a = field in manifest_a
    present_b = field in manifest_b
    actual_a = manifest_a.get(field)
    actual_b = manifest_b.get(field)
    if not present_a or not present_b:
        return {
            "status": "missing",
            "required": True,
            "a": actual_a,
            "b": actual_b,
            "expected_a": expected_a,
            "expected_b": expected_b,
            "message": f"{field} must be present in both manifests",
        }
    if actual_a != expected_a or actual_b != expected_b:
        return {
            "status": "mismatch",
            "required": True,
            "a": actual_a,
            "b": actual_b,
            "expected_a": expected_a,
            "expected_b": expected_b,
            "message": (
                f"arm A must declare {expected_a!r} and arm B "
                f"must declare {expected_b!r}"
            ),
        }
    return {
        "status": "ok",
        "required": True,
        "a": actual_a,
        "b": actual_b,
        "expected_a": expected_a,
        "expected_b": expected_b,
        "message": "matched frozen arm roles",
    }


def _value_check(actual: Any, expected: Any, message: str) -> dict[str, Any]:
    if actual is None:
        return {
            "status": "missing",
            "required": True,
            "actual": None,
            "expected": expected,
            "message": message,
        }
    if actual != expected:
        return {
            "status": "mismatch",
            "required": True,
            "actual": actual,
            "expected": expected,
            "message": message,
        }
    return {
        "status": "ok",
        "required": True,
        "actual": actual,
        "expected": expected,
        "message": "matched",
    }


def _clean_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


__all__ = [
    "BenchmarkArm",
    "CalibrationArtifact",
    "CLAIM_ALPHA",
    "MAX_FP_INCREASE",
    "MIN_DISCORDANT_FOR_NO_DIFFERENCE",
    "PRECISION_TOLERANCE",
    "audit_execution",
    "audit_quality_inputs",
    "benchmark_quality",
    "calibration_sha256",
    "freeze_calibration",
]
