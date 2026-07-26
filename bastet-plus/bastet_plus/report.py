"""Report writers: csv, json, md, sarif.

SARIF is the addition that matters. The original emitted csv/json/md/pdf, none
of which any code host understands, so CI integration meant reading a PDF.
SARIF renders as inline annotations on the changed lines in GitHub and GitLab
-- which is only possible now that findings carry line numbers.
"""

from __future__ import annotations

import csv
import json
import os

from .schema import Finding

_SARIF_LEVEL = {"high": "error", "medium": "warning", "low": "note"}


def _ensure(path: str) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)


def write_json(findings: list[Finding], path: str, stats: dict | None = None) -> None:
    _ensure(path)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"stats": stats or {}, "findings": [f.as_dict() for f in findings]},
                  fh, indent=2, ensure_ascii=False)


def write_csv(findings: list[Finding], path: str) -> None:
    _ensure(path)
    cols = ["file", "line", "severity", "confidence", "function_name", "summary",
            "detector", "votes", "samples", "grounded", "recommendation"]
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(cols)
        for f in findings:
            d = f.as_dict()
            w.writerow([d.get(c, "") for c in cols])


def write_md(findings: list[Finding], path: str, stats: dict | None = None) -> str:
    lines = ["# Bastet+ audit report", ""]
    if stats:
        lines += ["| metric | value |", "| --- | --- |"]
        lines += [f"| {k} | {v} |" for k, v in stats.items()]
        lines.append("")
    if not findings:
        lines.append("No vulnerabilities found.")
    else:
        by_sev: dict[str, int] = {}
        for f in findings:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        lines.append("**" + ", ".join(f"{v} {k}" for k, v in sorted(by_sev.items())) + "**")
        lines.append("")
        for i, f in enumerate(findings, 1):
            loc = f"{f.file}:{f.line}" if f.line else f.file
            lines += [
                f"## {i}. [{f.severity.upper()}] {f.summary}",
                "",
                f"- **Location:** `{loc}` in `{f.function_name}`",
                f"- **Confidence:** {f.confidence:.2f}"
                + (f" (agreed by {f.votes}/{f.samples} samples)" if f.samples > 1 else ""),
                f"- **Detector:** `{f.detector}`",
                "",
                f.description,
                "",
            ]
            if f.code_snippet:
                lines += ["```solidity", "\n".join(f.code_snippet), "```", ""]
            if f.recommendation:
                lines += ["**Recommendation:** " + f.recommendation, ""]
            if f.verdict_reason:
                lines += ["> Verifier: " + f.verdict_reason, ""]
    text = "\n".join(lines)
    if path:
        _ensure(path)
        open(path, "w", encoding="utf-8").write(text)
    return text


def write_sarif(findings: list[Finding], path: str, tool_version: str = "0.2.0") -> None:
    """SARIF 2.1.0 -- consumable by GitHub code scanning and GitLab."""
    rules, rule_index = [], {}
    results = []
    for f in findings:
        rid = (f.detector or "bastet").split(",")[0] or "bastet"
        if rid not in rule_index:
            rule_index[rid] = len(rules)
            rules.append({
                "id": rid,
                "shortDescription": {"text": rid},
                "help": {"text": f.recommendation or "See finding description."},
            })
        results.append({
            "ruleId": rid,
            "ruleIndex": rule_index[rid],
            "level": _SARIF_LEVEL.get(f.severity, "warning"),
            "message": {"text": f"{f.summary} (function `{f.function_name}`, confidence {f.confidence:.2f})"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file.replace("\\", "/")},
                    "region": {"startLine": f.line or 1},
                }
            }],
            "properties": {"confidence": f.confidence, "votes": f.votes,
                           "samples": f.samples, "grounded": f.grounded},
        })
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Bastet+", "version": tool_version,
                                "informationUri": "https://github.com/OneSavieLabs/Bastet",
                                "rules": rules}},
            "results": results,
        }],
    }
    _ensure(path)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2)


WRITERS = {"json": write_json, "csv": write_csv, "md": write_md, "sarif": write_sarif}


def write_all(findings: list[Finding], out_dir: str, name: str, formats, stats: dict | None = None) -> list[str]:
    written = []
    for fmt in formats:
        path = os.path.join(out_dir, f"{name}.{fmt}")
        if fmt == "json":
            write_json(findings, path, stats)
        elif fmt == "md":
            write_md(findings, path, stats)
        elif fmt == "csv":
            write_csv(findings, path)
        elif fmt == "sarif":
            write_sarif(findings, path)
        else:
            continue
        written.append(path)
    return written
