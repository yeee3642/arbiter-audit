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
from datetime import datetime, timezone
from pathlib import Path

from .routing import Task
from .llm import LLMResult
from . import findings as findings_mod
from .findings import Finding


def task_id(task: Task, model: str, prompt_version: str) -> str:
    repo = task.slices[0].repo if task.slices else ""
    parts = [task.detector.id, prompt_version, model, repo, task.path,
             *sorted(sl.id for sl in task.slices)]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


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

    def write_manifest(self, cfg: dict) -> None:
        """Persist the run configuration (fields per DESIGN §1.6; caller supplies
        them). run_id and created_at are filled in when absent, and created_at from
        an earlier write survives so resuming does not rewrite history."""
        manifest = dict(cfg)
        manifest.setdefault("run_id", self.run_dir.name)
        if "created_at" not in manifest and self.manifest_path.exists():
            try:
                manifest["created_at"] = json.loads(
                    self.manifest_path.read_text()).get("created_at")
            except (json.JSONDecodeError, OSError):
                pass
        manifest.setdefault(
            "created_at", datetime.now(timezone.utc).isoformat(timespec="seconds"))
        self.manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True))

    def read_manifest(self) -> dict:
        return json.loads(self.manifest_path.read_text())

    # -- task plan ----------------------------------------------------------

    def write_tasks(self, tasks: list[Task], model: str, prompt_version: str) -> None:
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
                    done.add(json.loads(line)["task_id"])
                except (json.JSONDecodeError, KeyError):
                    continue  # torn tail from a hard kill; the task will rerun
        return done

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

    def load_findings(self) -> list[Finding]:
        """All findings from results.jsonl, first record per task_id winning: resume
        after a crash may append a duplicate, and the earlier line is the one whose
        write completed."""
        out: list[Finding] = []
        seen: set[str] = set()
        if not self.results_path.exists():
            return out
        with self.results_path.open() as fh:
            for line in fh:
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                tid = rec.get("task_id")
                if tid in seen:
                    continue
                seen.add(tid)
                for d in rec.get("findings") or []:
                    if isinstance(d, dict):
                        out.append(findings_mod.from_dict(d))
        return out

    def export_findings(self) -> Path:
        """Write findings.json (end-of-run convenience view over results.jsonl)."""
        data = [findings_mod.to_dict(f) for f in self.load_findings()]
        self.findings_path.write_text(json.dumps(data, indent=2))
        return self.findings_path
