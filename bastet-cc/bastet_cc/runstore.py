"""Run persistence: append-only results, a manifest, and free resume.

A run must survive being killed at any instant -- broadcast arms take tens of
thousands of calls and the endpoint is shared. The contract is minimal: every
completed task is exactly one line in results.jsonl, written and flushed before the
executor moves on; resume is `done_ids()` minus nothing. A torn final line from a
hard kill is skipped on read and the task simply reruns.

`task_id` folds in prompt_version and model, so any change that would alter an answer
changes the id and the cache invalidates itself instead of serving stale output
(DESIGN §1.6). Slice ids are sorted first: routing order is an implementation detail,
the same work must not get two ids.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from .routing import Task
from .llm import LLMResult
from . import findings as findings_mod
from .findings import Finding


_VALID_VERDICTS = frozenset({"unverified", "confirmed", "rejected", "uncertain"})


class RunConfigurationMismatch(ValueError):
    """A populated run directory cannot be rebound to a different profile."""


def task_id(
    task: Task,
    model: str,
    prompt_version: str,
) -> str:
    repo = task.slices[0].repo if task.slices else ""
    parts = [task.detector.id, prompt_version, model, repo, task.path,
             *sorted(sl.id for sl in task.slices)]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


def task_plan_sha256(task_ids: Iterable[str]) -> str:
    canonical = "\n".join(sorted({str(value) for value in task_ids}))
    return hashlib.sha256(canonical.encode()).hexdigest()


class RunStore:
    def __init__(self, run_dir: Path):
        self.run_dir = Path(run_dir)
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.manifest_path = self.run_dir / "manifest.json"
        self.results_path = self.run_dir / "results.jsonl"
        self.tasks_path = self.run_dir / "tasks.jsonl"
        self.findings_path = self.run_dir / "findings.json"
        # Hand this to LLMClient(log_path=...) so per-call usage lands in the run dir.
        self.llm_log_path = self.run_dir / "llm_log.jsonl"

    # -- manifest -----------------------------------------------------------

    def write_manifest(self, cfg: dict, *, strict_resume: bool = False) -> None:
        """Persist the run configuration (fields per DESIGN §1.6; caller supplies
        them). run_id and created_at are filled in when absent, and created_at from
        an earlier write survives so resuming does not rewrite history.

        strict_resume is the scan path's fail-closed mode: once a manifest exists,
        immutable run configuration may not change, and existing task/result files
        may never be rebound when the manifest is missing.
        """
        manifest = dict(cfg)
        manifest.setdefault("run_id", self.run_dir.name)
        existing: dict | None = None
        if self.manifest_path.exists():
            try:
                loaded = json.loads(self.manifest_path.read_text())
                if isinstance(loaded, dict):
                    existing = loaded
                elif strict_resume:
                    raise RunConfigurationMismatch(
                        "existing run manifest must be a JSON object")
            except (json.JSONDecodeError, OSError) as exc:
                if strict_resume:
                    raise RunConfigurationMismatch(
                        "existing run manifest is unreadable") from exc
        elif strict_resume and (
            self.results_path.exists() or self.tasks_path.exists()
        ):
            raise RunConfigurationMismatch(
                "existing run artifacts have no manifest")

        if strict_resume and existing is not None:
            immutable_existing = {
                key: value for key, value in existing.items()
                if key not in {"created_at", "execution"}
            }
            if immutable_existing != manifest:
                changed = sorted(
                    key for key in set(immutable_existing) | set(manifest)
                    if immutable_existing.get(key) != manifest.get(key)
                )
                raise RunConfigurationMismatch(
                    "existing run configuration differs: "
                    + ", ".join(changed))
            return

        if "created_at" not in manifest and existing is not None:
            manifest["created_at"] = existing.get("created_at")
        manifest.setdefault(
            "created_at", datetime.now(timezone.utc).isoformat(timespec="seconds"))
        self.manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True))

    def read_manifest(self) -> dict:
        return json.loads(self.manifest_path.read_text())

    def update_execution(self, summary: dict) -> None:
        manifest = self.read_manifest()
        manifest["execution"] = dict(summary)
        self.manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True))

    # -- task plan ----------------------------------------------------------

    def write_tasks(
        self,
        tasks: list[Task],
        model: str,
        prompt_version: str,
    ) -> None:
        """Snapshot the plan (one line per task) so a run is auditable without
        re-planning: which detector saw which file, and at what size."""
        with self.tasks_path.open("w") as fh:
            for t in tasks:
                fh.write(json.dumps({
                    "task_id": task_id(t, model, prompt_version),
                    "detector_id": t.detector.id,
                    "repo": t.slices[0].repo if t.slices else "",
                    "path": t.path,
                    "slice_ids": sorted(sl.id for sl in t.slices),
                    "code_chars": t.code_chars,
                }) + "\n")

    # -- results ------------------------------------------------------------

    def done_ids(self) -> set[str]:
        done: set[str] = set()
        if not self.results_path.exists():
            return done
        with self.results_path.open() as fh:
            for line in fh:
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue  # torn tail from a hard kill; the task will rerun
                if not isinstance(row, dict):
                    continue
                tid = row.get("task_id")
                if isinstance(tid, str) and tid:
                    done.add(tid)
        return done

    def planned_ids(self) -> set[str]:
        planned: set[str] = set()
        if not self.tasks_path.exists():
            return planned
        with self.tasks_path.open() as fh:
            for line in fh:
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(row, dict):
                    continue
                tid = row.get("task_id")
                if isinstance(tid, str) and tid:
                    planned.add(tid)
        return planned

    def result_summary(self, planned_ids: Iterable[str]) -> dict:
        planned = {str(value) for value in planned_ids}
        records: dict[str, dict] = {}
        invalid_result_rows = 0
        if self.results_path.exists():
            with self.results_path.open() as fh:
                for line in fh:
                    try:
                        row = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if not isinstance(row, dict):
                        invalid_result_rows += 1
                        continue
                    tid = row.get("task_id")
                    if not isinstance(tid, str) or not tid:
                        invalid_result_rows += 1
                        continue
                    records.setdefault(tid, row)

        completed = planned & set(records)
        unexpected = set(records) - planned
        error_counts = Counter(
            str(records[tid].get("error"))
            for tid in completed if records[tid].get("error")
        )
        failed = sum(error_counts.values())
        successful = len(completed) - failed
        return {
            "planned_tasks": len(planned),
            "completed_tasks": len(completed),
            "successful_tasks": successful,
            "failed_tasks": failed,
            "missing_tasks": len(planned - completed),
            "unexpected_tasks": len(unexpected),
            "invalid_result_rows": invalid_result_rows,
            "error_counts": dict(sorted(error_counts.items())),
            "planned_task_ids_sha256": task_plan_sha256(planned),
            "completed_task_ids_sha256": task_plan_sha256(completed),
        }

    def claim_manifest(self) -> dict:
        """Manifest view with execution evidence recomputed from task/result logs."""
        manifest = self.read_manifest()
        recorded = manifest.get("execution")
        recorded = recorded if isinstance(recorded, dict) else {}
        actual = self.result_summary(self.planned_ids())
        recorded_matches = all(
            recorded.get(key) == value for key, value in actual.items()
        )
        actual["scan_completed"] = (
            recorded.get("scan_completed") is True and recorded_matches
        )
        manifest["execution"] = actual
        return manifest

    def append(self, task_id: str, result: LLMResult, findings: list[dict]) -> None:
        line = json.dumps({
            "task_id": task_id,
            "error": result.error,
            "findings": findings,
            "usage": {
                "model": result.model,
                "input_tokens": result.input_tokens,
                "output_tokens": result.output_tokens,
                "latency_s": round(result.latency_s, 3),
                "attempts": result.attempts,
            },
        })
        with self.results_path.open("a") as fh:
            fh.write(line + "\n")
            fh.flush()

    def load_findings(
        self,
        apply_verification: bool = True,
        allowed_task_ids: set[str] | None = None,
    ) -> list[Finding]:
        """All findings from results.jsonl, first record per task_id winning: resume
        after a crash may append a duplicate, and the earlier line is the one whose
        write completed.

        Falls back to findings.json when results.jsonl is absent. This is not a
        convenience: results.jsonl embeds contract source verbatim and is
        gitignored, so on a fresh clone it is the *only* artefact a run has.
        Without the fallback every scoring and comparison command reports zero
        findings for every committed run, and nothing in this repository is
        reproducible by a reader who does not also hold the 6.8 GB corpus.
        """
        out: list[Finding] = []
        seen: set[str] = set()
        if not self.results_path.exists():
            if allowed_task_ids is not None:
                return []
            out = self._load_exported()
            return self._apply_verification_overlays(out) if apply_verification else out
        with self.results_path.open() as fh:
            for line in fh:
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(rec, dict):
                    continue
                tid = rec.get("task_id")
                if not isinstance(tid, str) or not tid:
                    continue
                if allowed_task_ids is not None and tid not in allowed_task_ids:
                    continue
                if tid in seen:
                    continue
                seen.add(tid)
                for d in rec.get("findings") or []:
                    if isinstance(d, dict):
                        out.append(findings_mod.from_dict(d))
        return self._apply_verification_overlays(out) if apply_verification else out

    def _apply_verification_overlays(self, raw: list[Finding]) -> list[Finding]:
        """Return copies carrying the latest valid verify.jsonl decision.

        results.jsonl remains detector-owned and immutable. New overlay records
        match by findings.finding_key(); legacy v1 records are matched by their
        historical verify_id when the run manifest supplies the model, then by a
        conservative location tuple only when that exact reconstruction is not
        possible. Later lines win so a new prompt/schema version can supersede an
        older adjudication without rewriting history.
        """
        path = self.run_dir / "verify.jsonl"
        if not raw or not path.exists():
            return raw

        by_key: dict[str, dict] = {}
        by_verify_id: dict[str, dict] = {}
        by_legacy_site: dict[tuple[str, ...], list[dict]] = {}
        try:
            lines = path.open()
        except OSError:
            return raw
        with lines:
            for line in lines:
                try:
                    rec = json.loads(line)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    continue
                if not isinstance(rec, dict) or rec.get("verdict") not in _VALID_VERDICTS:
                    continue
                if "finding_key" in rec:
                    key = rec.get("finding_key")
                    if not isinstance(key, str) or not key:
                        continue
                    by_key[key] = rec
                    continue
                # Only genuinely legacy rows, where finding_key is absent,
                # may participate in broader legacy-id/site matching.
                vid = rec.get("adjudication_id") or rec.get("verify_id")
                if isinstance(vid, str) and vid:
                    by_verify_id[vid] = rec
                site = self._legacy_site_from_record(rec)
                if site is not None:
                    by_legacy_site.setdefault(site, []).append(rec)

        model = ""
        if self.manifest_path.exists():
            try:
                model = str(json.loads(self.manifest_path.read_text()).get("model") or "")
            except (json.JSONDecodeError, OSError):
                pass

        raw_site_counts: dict[tuple[str, ...], int] = {}
        for finding in raw:
            site = self._legacy_site(finding)
            raw_site_counts[site] = raw_site_counts.get(site, 0) + 1

        out: list[Finding] = []
        for finding in raw:
            rec = by_key.get(findings_mod.finding_key(finding))
            if rec is None and model:
                rec = by_verify_id.get(self._legacy_verify_id(finding, model))
            # Site-only matching exists solely for legacy runs whose manifest
            # cannot supply the model needed to reconstruct verify_id. It is
            # safe only when both sides are unique; otherwise two distinct
            # claims in one function could inherit the same verdict.
            site = self._legacy_site(finding)
            legacy_rows = by_legacy_site.get(site, [])
            if (
                rec is None
                and not model
                and raw_site_counts.get(site) == 1
                and len(legacy_rows) == 1
            ):
                rec = legacy_rows[0]
            if rec is None:
                out.append(finding)
                continue
            adjudication_id = str(
                rec.get("adjudication_id") or rec.get("verify_id") or "")
            reason = str(
                rec.get("reason_code") or rec.get("reason")
                or rec.get("reject_reason") or "")
            version = str(
                rec.get("adjudication_version") or rec.get("schema_version")
                or rec.get("prompt_version") or "legacy-v1")
            out.append(replace(
                finding,
                verdict=str(rec["verdict"]),
                adjudication_id=adjudication_id,
                adjudication_reason=reason,
                adjudication_version=version,
            ))
        return out

    @staticmethod
    def _legacy_site(finding: Finding) -> tuple[str, ...]:
        return (
            finding.task_id, finding.repo, finding.detector_id, finding.tag,
            finding.path, finding.contract, finding.function,
        )

    @staticmethod
    def _legacy_site_from_record(rec: dict) -> tuple[str, ...] | None:
        fields = ("task_id", "repo", "detector_id", "tag", "path", "contract", "function")
        if not all(field in rec for field in fields):
            return None
        return tuple(str(rec.get(field) or "") for field in fields)

    @staticmethod
    def _legacy_verify_id(
        finding: Finding, model: str, prompt_version: str = "v1"
    ) -> str:
        """Reconstruct verify.verify_id without importing verify (which imports us)."""
        parts = [
            finding.repo, finding.detector_id, finding.tag, finding.path,
            finding.contract, finding.function, finding.evidence,
            finding.description, model, prompt_version,
        ]
        return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]

    def _load_exported(self) -> list[Finding]:
        """findings.json, the committed view of a run.

        Deliberately no task_id deduplication: export_findings() already applied
        it when the file was written, and re-applying it here would silently drop
        findings from any run whose exporter predated task_id being recorded.
        """
        if not self.findings_path.exists():
            return []
        try:
            data = json.loads(self.findings_path.read_text())
        except (json.JSONDecodeError, OSError):
            return []
        if not isinstance(data, list):
            return []
        return [findings_mod.from_dict(d) for d in data if isinstance(d, dict)]

    def has_results(self) -> bool:
        """True when the raw append-only log exists, i.e. this run can be resumed.

        A run loaded from findings.json alone is scoreable but not resumable --
        done_ids() has nothing to read, so resuming would redo every task.
        """
        return self.results_path.exists()

    def export_findings(self) -> Path:
        """Write findings.json (end-of-run convenience view over results.jsonl)."""
        data = [findings_mod.to_dict(f) for f in self.load_findings()]
        self.findings_path.write_text(json.dumps(data, indent=2))
        return self.findings_path
