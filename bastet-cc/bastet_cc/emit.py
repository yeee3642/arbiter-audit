"""Deliverables: SARIF, Markdown, JSON.

Upstream Bastet ships csv/json/md/pdf, so reports are table stakes and their
absence here was a real gap. SARIF is the one that is not parity.

SARIF 2.1.0 is what GitHub code scanning ingests. Upload it from a workflow and
every finding becomes an annotation on the exact line of the pull request that
introduced it, with the detector's rule text attached. That requires a file path
and a line range per result, and upstream's `AuditReport`
(`cli/models/audit_report.py`) carries neither -- its fields are summary,
severity, `vulnerability_details{function_name, description}`, code_snippet and
recommendation. The file is attached outside the model as
`os.path.basename(contract_file)`, so two `Vault.sol` in different directories are
indistinguishable in their report, and there is no line number anywhere.

That is not an oversight to be patched in a afternoon: it follows from the payload.
Their scanner posts a whole file to a webhook, so the model's answer cannot be
bound back to a parsed function, and there is nothing to write a region from. Our
routed arm asks about one function whose span the tree-sitter index already knows,
which is why `Finding.start_line` exists and why this module can exist.

Honesty constraints this module keeps:

- A finding with no parser-backed span becomes a **file-level** SARIF result, not
  a result at line 1. Line 1 would be a fabricated location that a reviewer would
  chase.
- `partialFingerprints` are derived from the site, not from the description, so a
  reworded model output does not reopen a dismissed alert.
- Findings the verifier rejected are excluded from SARIF by default. SARIF is a
  reviewer-facing surface; shipping alarms we already refuted spends the one
  resource a PR gate has, which is the reviewer's willingness to keep reading.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from typing import Iterable, Sequence

from .findings import Finding, asserted_span, line_span, localisation

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = ("https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
                "Schemata/sarif-schema-2.1.0.json")

TOOL_NAME = "Bastet-CC"
TOOL_URI = "https://github.com/ericchen913900/Aislop3"

# GitHub code scanning renders these three levels. Our severities map onto them
# directly; `note` is deliberately used for Low rather than suppressing it, so a
# Low finding is visible without failing a gate.
_SARIF_LEVEL = {"High": "error", "Medium": "warning", "Low": "note"}

# Verdicts excluded from reviewer-facing output. `rejected` means the refutation
# pass argued the finding away; `uncertain` is kept, because "we could not settle
# this" is information a reviewer can act on.
SUPPRESSED_VERDICTS = frozenset({"rejected"})


def _rule_id(finding: Finding) -> str:
    """One SARIF rule per detector, so GitHub groups alerts the way we group work."""
    return finding.detector_id or "bastet-cc/unknown"


def _fingerprint(finding: Finding) -> str:
    """Stable identity of a finding, for alert dedup across runs.

    Deliberately excludes the description and the line numbers. The description is
    model-authored and changes wording between runs; line numbers shift when code
    above them moves. Detector plus site plus subtag survives both, which is what
    makes "dismissed" stick in the GitHub UI.
    """
    key = "|".join((finding.detector_id, finding.path, finding.contract,
                    finding.function, finding.subtag))
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def reportable(findings: Iterable[Finding],
               suppressed: frozenset[str] = SUPPRESSED_VERDICTS) -> list[Finding]:
    return [f for f in findings if f.verdict not in suppressed]


# -- SARIF ----------------------------------------------------------------------


def to_sarif(findings: Iterable[Finding], *, detector_help: dict[str, str] | None = None,
             include_suppressed: bool = False, run_id: str = "") -> dict:
    """SARIF 2.1.0 log for GitHub code scanning.

    `detector_help` optionally maps detector id -> the detector's own prompt text,
    which GitHub shows as the rule description. Passing it turns each alert into
    something a reviewer can evaluate without opening this repository.
    """
    items = list(findings) if include_suppressed else reportable(findings)
    help_text = detector_help or {}

    rules: dict[str, dict] = {}
    results: list[dict] = []

    for f in items:
        rid = _rule_id(f)
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": rid.replace("__", ".").replace("_", " "),
                "shortDescription": {"text": f.tag or rid},
                "fullDescription": {
                    "text": help_text.get(rid) or f"Bastet-CC detector {rid} ({f.tag})."
                },
                "defaultConfiguration": {
                    "level": _SARIF_LEVEL.get(f.severity, "warning")},
                "properties": {"tags": [t for t in (f.tag,) if t]},
            }

        # Region provenance decides whether we may point at a line at all.
        #   parser -- span came from the tree-sitter index: annotate it.
        #   site   -- the function resolved but the lines are the model's: annotate
        #             as best effort and say so, since a reviewer landing two lines
        #             off can still find it from the function name.
        #   none   -- only the file is known. `startLine: 1` here would be a
        #             fabricated location and a reviewer would chase it.
        where = localisation(f)
        span = line_span(f) if where == "parser" else (
            asserted_span(f) if where == "site" else None)

        location: dict = {
            "physicalLocation": {
                "artifactLocation": {"uri": f.path, "uriBaseId": "%SRCROOT%"},
            }
        }
        if span is not None:
            start, end = span
            location["physicalLocation"]["region"] = {
                "startLine": start, "endLine": end}

        message = f.description or f"{f.tag}: {f.subtag or rid} in {f.function}"
        if where == "site":
            message += ("\n\n(the function was matched against the parsed index, but "
                        "this line range is the model's own claim and was not "
                        "verified)")
        elif where == "none":
            message += ("\n\n(no line range: produced by an arm that sends whole "
                        "files, so nothing bound it to a parsed function)")

        result = {
            "ruleId": rid,
            "level": _SARIF_LEVEL.get(f.severity, "warning"),
            "message": {"text": message},
            "locations": [location],
            "partialFingerprints": {"bastetCcSite/v1": _fingerprint(f)},
            "properties": {
                "tag": f.tag,
                "subtag": f.subtag,
                "severity": f.severity,
                "confidence": f.confidence,
                "verdict": f.verdict,
                "contract": f.contract,
                "function": f.function,
                "repo": f.repo,
                "localisation": where,
            },
        }
        if f.verdict in SUPPRESSED_VERDICTS:
            # Only reachable with include_suppressed=True. Marked rather than
            # silently mixed in, so a rejected finding cannot be mistaken for a live one.
            result["suppressions"] = [
                {"kind": "external", "justification": f"verdict={f.verdict}"}]
        results.append(result)

    return {
        "version": SARIF_VERSION,
        "$schema": SARIF_SCHEMA,
        "runs": [{
            "tool": {"driver": {
                "name": TOOL_NAME,
                "informationUri": TOOL_URI,
                "rules": [rules[k] for k in sorted(rules)],
            }},
            "results": results,
            "properties": {
                "runId": run_id,
                "localisation": {
                    k: sum(1 for r in results
                           if r["properties"]["localisation"] == k)
                    for k in ("parser", "site", "none")
                },
                "totalResults": len(results),
            },
        }],
    }


# -- Markdown -------------------------------------------------------------------

_SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2}


def to_markdown(findings: Iterable[Finding], *, title: str = "Bastet-CC audit report",
                repo_url: str = "", include_suppressed: bool = False) -> str:
    """A report a human reads, ordered by severity then by site.

    `repo_url` turns each site into a permalink. Without it the location is still
    printed as `path:line`, which most editors and terminals make clickable.
    """
    items = list(findings) if include_suppressed else reportable(findings)
    items.sort(key=lambda f: (_SEVERITY_ORDER.get(f.severity, 9), f.path,
                              f.start_line, f.function))

    counts = Counter(f.severity for f in items)
    where = Counter(localisation(f) for f in items)

    out = [f"# {title}", ""]
    if not items:
        out += ["No findings.", ""]
        return "\n".join(out)

    out += [
        f"{len(items)} findings — "
        + ", ".join(f"{counts[s]} {s}" for s in ("High", "Medium", "Low") if counts[s]),
        "",
        f"Localisation: {where['parser']} exact (parser-backed), "
        f"{where['site']} function matched with a model-asserted line range, "
        f"{where['none']} file-level only.",
        "",
    ]

    by_tag: dict[str, list[Finding]] = defaultdict(list)
    for f in items:
        by_tag[f.tag or "Untagged"].append(f)

    out += ["| severity | tag | location | detector |", "|---|---|---|---|"]
    for f in items:
        out.append(f"| {f.severity} | {f.tag} | {_location(f, repo_url)} "
                   f"| `{f.detector_id}` |")
    out.append("")

    for tag in sorted(by_tag):
        out += [f"## {tag}", ""]
        for f in by_tag[tag]:
            out += [
                f"### {f.severity} — {f.contract}.{f.function}"
                + (f" ({f.subtag})" if f.subtag else ""),
                "",
                f"**Location** {_location(f, repo_url)}  ",
                f"**Detector** `{f.detector_id}`  ",
                f"**Confidence** {f.confidence:.2f}  "
                + (f"**Verdict** {f.verdict}" if f.verdict != "unverified" else ""),
                "",
                f.description or "_no description_",
                "",
            ]
            place = localisation(f)
            if place == "site":
                out += ["> The function was matched against the parsed index, but the "
                        "line range above is the model's own claim and was not "
                        "verified.", ""]
            elif place == "none":
                out += ["> File-level only: this finding came from an arm that sends "
                        "whole files, so nothing bound it to a parsed function.", ""]
    return "\n".join(out)


def _location(f: Finding, repo_url: str = "") -> str:
    place = localisation(f)
    span = line_span(f) if place == "parser" else (
        asserted_span(f) if place == "site" else None)
    label = f.path if span is None else f"{f.path}:{span[0]}"
    if place == "site":
        label += "?"            # the line is asserted, not verified
    if not repo_url:
        return f"`{label}`"
    frag = "" if span is None else f"#L{span[0]}-L{span[1]}"
    return f"[`{label}`]({repo_url.rstrip('/')}/{f.path}{frag})"


# -- JSON -----------------------------------------------------------------------


def to_json(findings: Iterable[Finding], *, include_suppressed: bool = False) -> str:
    from . import findings as findings_mod

    items = list(findings) if include_suppressed else reportable(findings)
    return json.dumps([findings_mod.to_dict(f) for f in items], indent=2)


# -- summary for a gate ---------------------------------------------------------


def gate_summary(findings: Iterable[Finding], *,
                 fail_on: Sequence[str] = ("High",)) -> dict:
    """Whether a CI gate should fail, and the counts behind that.

    Separated from the emitters because a gate decision is policy: a repository
    may want High to block and Medium to annotate. Suppressed verdicts never
    count toward a failure -- failing a build on a finding our own verifier
    refuted is how a security gate gets switched off.
    """
    items = reportable(findings)
    counts = Counter(f.severity for f in items)
    blocking = sum(counts[s] for s in fail_on)
    return {
        "total": len(items),
        "counts": {s: counts[s] for s in ("High", "Medium", "Low") if counts[s]},
        "suppressed": sum(1 for f in findings if f.verdict in SUPPRESSED_VERDICTS),
        "localisation": dict(Counter(localisation(f) for f in items)),
        "fail_on": list(fail_on),
        "blocking": blocking,
        "passed": blocking == 0,
    }
