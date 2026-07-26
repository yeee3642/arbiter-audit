"""Benchmark runner: run both harnesses over the labelled cases and diff them."""

from __future__ import annotations

import json
import os
import pathlib
import time

from .config import LLMConfig, PipelineConfig
from .detectors import Detector, load_detectors
from .llm import LLMClient, Usage
from .metrics import EvalResult, evaluate, render_table
from .pipeline import run_enhanced, run_legacy


def load_labels(path: str) -> dict:
    return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))


def relevant_detectors(prompt_dir: str, labels: dict) -> list[Detector]:
    """Only the detectors the benchmark can actually score.

    Running all 56 over a 20-file benchmark would burn tokens on classes the
    labels say nothing about, and any finding from them is unscoreable -- it is
    neither a true nor a false positive, just noise in the cost column.
    """
    names = sorted(labels["detector_class"].keys())
    dets = load_detectors(prompt_dir, names=names)
    missing = set(names) - {d.name for d in dets}
    if missing:
        print(f"  ! labels reference unknown detectors: {sorted(missing)}")
    return dets


def run_arm(arm: str, cases_dir: str, labels: dict, detectors: list[Detector],
            llm_cfg: LLMConfig, pipe_cfg: PipelineConfig, verbose: bool = True):
    """Run one harness over every benchmark case. Returns (results, stats, usage)."""
    usage = Usage()
    client = LLMClient(llm_cfg, usage)
    results: dict[str, list] = {}
    per_file_stats: list[dict] = []
    t0 = time.time()

    for case in labels["cases"]:
        path = os.path.join(cases_dir, case["file"])
        if arm == "legacy":
            res = run_legacy(path, detectors, client, llm_cfg)
        else:
            res = run_enhanced(path, detectors, client, llm_cfg, pipe_cfg)
        for f in res.findings:
            f.file = case["file"]  # label-relative, so metrics can join
        results[case["file"]] = res.findings
        per_file_stats.append(res.stats)
        if verbose:
            truth = ",".join(case["classes"]) or "clean"
            print(f"  [{arm:8}] {case['file']:32} truth={truth:16} "
                  f"reported={len(res.findings):3d}  ({res.stats.get('wall_seconds', 0)}s)")

    agg = {
        "arm": arm,
        "files": len(labels["cases"]),
        "detectors": len(detectors),
        "wall_seconds": round(time.time() - t0, 1),
        "llm_requests": sum(s.get("llm_requests", 0) for s in per_file_stats),
        "slices": sum(s.get("slices", 0) for s in per_file_stats),
        "raw_findings": sum(s.get("raw_findings", 0) for s in per_file_stats),
        "reported": sum(s.get("reported", 0) for s in per_file_stats),
        "detector_errors": sum(s.get("detector_errors", 0) for s in per_file_stats),
    }
    for k in ("strict_parse_failures", "severity_silently_coerced", "dropped_by_vote",
              "dropped_ungrounded", "dropped_by_verifier", "merged_duplicates"):
        total = sum(s.get(k, 0) for s in per_file_stats)
        if total or k in ("strict_parse_failures", "dropped_by_verifier"):
            agg[k] = total
    agg.update(usage.as_dict(llm_cfg))
    agg["parse_ladder"] = dict(client.parse_stats)
    return results, agg, usage


def _delta(a: float, b: float) -> str:
    d = b - a
    sign = "+" if d >= 0 else ""
    return f"{sign}{d:.3f}"


def comparison_table(legacy: EvalResult, enhanced: EvalResult,
                     legacy_stats: dict, enhanced_stats: dict) -> str:
    lo, eo = legacy.overall, enhanced.overall
    lf, efl = legacy.file_level, enhanced.file_level
    rows = [
        ["--- file level: does this file need review? ---", "", "", ""],
        ["File-level precision", f"{lf.precision:.3f}", f"{efl.precision:.3f}", _delta(lf.precision, efl.precision)],
        ["File-level recall", f"{lf.recall:.3f}", f"{efl.recall:.3f}", _delta(lf.recall, efl.recall)],
        ["File-level F1", f"{lf.f1:.3f}", f"{efl.f1:.3f}", _delta(lf.f1, efl.f1)],
        ["File-level TP/FP/FN/TN", f"{lf.tp}/{lf.fp}/{lf.fn}/{lf.tn}", f"{efl.tp}/{efl.fp}/{efl.fn}/{efl.tn}", ""],
        ["--- per (file, class) pair: strict attribution ---", "", "", ""],
        ["Precision", f"{lo.precision:.3f}", f"{eo.precision:.3f}", _delta(lo.precision, eo.precision)],
        ["Recall", f"{lo.recall:.3f}", f"{eo.recall:.3f}", _delta(lo.recall, eo.recall)],
        ["F1", f"{lo.f1:.3f}", f"{eo.f1:.3f}", _delta(lo.f1, eo.f1)],
        ["Accuracy", f"{lo.accuracy:.3f}", f"{eo.accuracy:.3f}", _delta(lo.accuracy, eo.accuracy)],
        ["False-positive rate", f"{lo.fpr:.3f}", f"{eo.fpr:.3f}", _delta(lo.fpr, eo.fpr)],
        ["TP / FP / FN / TN", f"{lo.tp}/{lo.fp}/{lo.fn}/{lo.tn}", f"{eo.tp}/{eo.fp}/{eo.fn}/{eo.tn}", ""],
        ["Localization accuracy",
         f"{legacy.localization_hits}/{legacy.localization_total}",
         f"{enhanced.localization_hits}/{enhanced.localization_total}", ""],
        ["Findings with line number", str(legacy.line_hits), str(enhanced.line_hits), ""],
        ["Total findings reported", str(legacy.findings_reported), str(enhanced.findings_reported), ""],
        ["Noise per clean file",
         f"{legacy.as_dict()['noise_per_clean_file']}",
         f"{enhanced.as_dict()['noise_per_clean_file']}", ""],
        ["Clean files with an alarm",
         f"{legacy.clean_files_with_any_alarm}/{legacy.clean_files}",
         f"{enhanced.clean_files_with_any_alarm}/{enhanced.clean_files}", ""],
        ["Severity histogram",
         str(legacy.as_dict()["severity_histogram"]),
         str(enhanced.as_dict()["severity_histogram"]), ""],
        ["--- cost ---", "", "", ""],
        ["LLM requests", str(legacy_stats.get("llm_requests")), str(enhanced_stats.get("llm_requests")), ""],
        ["Total tokens", str(legacy_stats.get("total_tokens")), str(enhanced_stats.get("total_tokens")), ""],
        ["Wall seconds", str(legacy_stats.get("wall_seconds")), str(enhanced_stats.get("wall_seconds")), ""],
        ["--- harness health ---", "", "", ""],
        ["Strict JSON parse failures", str(legacy_stats.get("strict_parse_failures", "-")),
         str(enhanced_stats.get("strict_parse_failures", "n/a")), ""],
        ["Severity silently coerced", str(legacy_stats.get("severity_silently_coerced", "-")), "0", ""],
        ["Dropped: ungrounded evidence", "-", str(enhanced_stats.get("dropped_ungrounded", 0)), ""],
        ["Dropped: sample disagreement", "-", str(enhanced_stats.get("dropped_by_vote", 0)), ""],
        ["Dropped: verifier refuted", "-", str(enhanced_stats.get("dropped_by_verifier", 0)), ""],
        ["Duplicates merged", "-", str(enhanced_stats.get("merged_duplicates", 0)), ""],
    ]
    return render_table(rows, ["Metric", "Original (legacy)", "Bastet+", "Delta"])


def per_class_table(legacy: EvalResult, enhanced: EvalResult) -> str:
    rows = []
    for cls in sorted(set(legacy.per_class) | set(enhanced.per_class)):
        lc = legacy.per_class.get(cls)
        ec = enhanced.per_class.get(cls)
        rows.append([
            cls,
            f"{lc.precision:.2f}/{lc.recall:.2f}/{lc.f1:.2f}" if lc else "-",
            f"{ec.precision:.2f}/{ec.recall:.2f}/{ec.f1:.2f}" if ec else "-",
            f"{lc.tp}/{lc.fp}/{lc.fn}" if lc else "-",
            f"{ec.tp}/{ec.fp}/{ec.fn}" if ec else "-",
        ])
    return render_table(rows, ["Class", "Legacy P/R/F1", "Bastet+ P/R/F1",
                               "Legacy TP/FP/FN", "Bastet+ TP/FP/FN"])


def run_comparison(cases_dir: str, labels_path: str, prompt_dir: str,
                   llm_cfg: LLMConfig, pipe_cfg: PipelineConfig,
                   out_dir: str, arms: tuple[str, ...] = ("legacy", "enhanced"),
                   tag: str = "") -> dict:
    labels = load_labels(labels_path)
    detectors = relevant_detectors(prompt_dir, labels)
    print(f"Benchmark: {len(labels['cases'])} files x {len(detectors)} detectors "
          f"| model={llm_cfg.model}\n")

    out: dict = {"model": llm_cfg.model, "endpoint": llm_cfg.base_url,
                 "detectors": [d.name for d in detectors],
                 "pipeline_config": {k: getattr(pipe_cfg, k) for k in
                                     ("slice_code", "samples", "vote_threshold", "verify",
                                      "verify_votes", "drop_ungrounded", "max_slice_chars")},
                 "arms": {}}
    evals: dict[str, EvalResult] = {}

    for arm in arms:
        print(f"--- running {arm} ---")
        results, stats, _ = run_arm(arm, cases_dir, labels, detectors, llm_cfg, pipe_cfg)
        ev = evaluate(results, labels)
        evals[arm] = ev
        out["arms"][arm] = {"stats": stats, "metrics": ev.as_dict(),
                            "per_file": ev.per_file,
                            "findings": {k: [f.as_dict() for f in v] for k, v in results.items()}}
        print(f"    -> P={ev.overall.precision:.3f} R={ev.overall.recall:.3f} "
              f"F1={ev.overall.f1:.3f} | {stats['total_tokens']} tokens\n")

    if len(arms) == 2 and "legacy" in evals and "enhanced" in evals:
        table = comparison_table(evals["legacy"], evals["enhanced"],
                                 out["arms"]["legacy"]["stats"], out["arms"]["enhanced"]["stats"])
        cls_table = per_class_table(evals["legacy"], evals["enhanced"])
        print(table)
        print()
        print(cls_table)
        out["comparison_table"] = table
        out["per_class_table"] = cls_table

    os.makedirs(out_dir, exist_ok=True)
    suffix = f"_{tag}" if tag else ""
    dest = os.path.join(out_dir, f"comparison_{llm_cfg.model.replace('/', '_')}{suffix}.json")
    with open(dest, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2, ensure_ascii=False)
    print(f"\nfull results -> {dest}")
    return out
