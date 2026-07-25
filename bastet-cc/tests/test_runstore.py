"""RunStore: resume, torn tails, and the committed-artefact fallback.

The fallback is the load-bearing one. results.jsonl embeds contract source and is
gitignored, so on a fresh clone every run directory holds findings.json and
nothing else. Before the fallback existed, `evaluate`, `compare` and `structural`
all reported zero findings for every committed run -- silently, with a clean exit
code -- which made every published number unreproducible by anyone who did not
also hold the 6.8 GB corpus. A test guards it because the failure mode is quiet.
"""

from __future__ import annotations

import json

from bastet_cc.findings import Finding
from bastet_cc.llm import LLMResult
from bastet_cc.routing import Detector, Slice, Task
from bastet_cc.runstore import RunStore, task_id


def _task(det_id="d1", path="A.sol", repo="r1") -> Task:
    sl = Slice(repo=repo, path=path, contract="A", function="f",
               start_line=1, end_line=5, source="function f() {}")
    det = Detector(id=det_id, name="D", source_workflow="w", tags=["Slippage"],
                   routing_hints=["f"], prompt_chars=10)
    return Task(detector=det, path=path, slices=[sl])


def _result() -> LLMResult:
    return LLMResult(text="{}", parsed={}, model="m", input_tokens=1,
                     output_tokens=1, latency_s=0.1, attempts=1, error=None)


def _finding_dict(**kw) -> dict:
    base = {"repo": "r1", "detector_id": "d1", "tag": "Slippage", "subtag": "",
            "severity": "High", "path": "A.sol", "contract": "A", "function": "f",
            "description": "d", "evidence": "L1-L2", "confidence": 0.9,
            "verdict": "unverified", "task_id": "t0"}
    base.update(kw)
    return base


# -- the fallback ---------------------------------------------------------------


def test_load_findings_falls_back_to_committed_json(tmp_path):
    store = RunStore(tmp_path / "run")
    store.findings_path.write_text(json.dumps([
        _finding_dict(function="f"), _finding_dict(function="g")]))
    assert not store.results_path.exists()

    got = store.load_findings()
    assert [f.function for f in got] == ["f", "g"]
    assert all(isinstance(f, Finding) for f in got)


def test_results_jsonl_wins_when_both_exist(tmp_path):
    """The raw log is the source of truth; findings.json is a derived view.

    If they disagree the export is stale, and serving the stale copy would let a
    re-scored run silently report pre-fix numbers.
    """
    store = RunStore(tmp_path / "run")
    store.append("t1", _result(), [_finding_dict(function="from_results")])
    store.findings_path.write_text(json.dumps([_finding_dict(function="from_export")]))

    assert [f.function for f in store.load_findings()] == ["from_results"]


def test_fallback_does_not_dedup_by_task_id(tmp_path):
    """export_findings() already deduplicated; doing it twice drops real findings.

    Several findings legitimately share a task_id -- one LLM call can report more
    than one vulnerability -- so task_id is not a key over findings.json rows.
    """
    store = RunStore(tmp_path / "run")
    store.findings_path.write_text(json.dumps([
        _finding_dict(task_id="same", function="f"),
        _finding_dict(task_id="same", function="g"),
    ]))
    assert len(store.load_findings()) == 2


def test_no_artefacts_at_all_is_empty_not_an_error(tmp_path):
    assert RunStore(tmp_path / "run").load_findings() == []


def test_corrupt_findings_json_is_empty_not_a_crash(tmp_path):
    store = RunStore(tmp_path / "run")
    store.findings_path.write_text("{not json")
    assert store.load_findings() == []


def test_findings_json_wrong_shape_is_empty(tmp_path):
    store = RunStore(tmp_path / "run")
    store.findings_path.write_text(json.dumps({"findings": []}))
    assert store.load_findings() == []


def test_has_results_distinguishes_scoreable_from_resumable(tmp_path):
    store = RunStore(tmp_path / "run")
    store.findings_path.write_text(json.dumps([_finding_dict()]))
    assert store.load_findings()           # scoreable
    assert not store.has_results()         # but not resumable
    assert store.done_ids() == set()


# -- resume ---------------------------------------------------------------------


def test_done_ids_skips_a_torn_final_line(tmp_path):
    """A hard kill mid-write leaves a partial line; that task must simply rerun."""
    store = RunStore(tmp_path / "run")
    store.append("t1", _result(), [])
    store.append("t2", _result(), [])
    with store.results_path.open("a") as fh:
        fh.write('{"task_id": "t3", "findi')      # torn

    assert store.done_ids() == {"t1", "t2"}


def test_load_findings_keeps_first_record_per_task_id(tmp_path):
    """Resume can append a duplicate; the completed earlier write is the real one."""
    store = RunStore(tmp_path / "run")
    store.append("t1", _result(), [_finding_dict(description="first")])
    store.append("t1", _result(), [_finding_dict(description="second")])

    got = store.load_findings()
    assert [f.description for f in got] == ["first"]


def test_task_id_changes_with_model_and_prompt_version():
    """The id folds in model and prompt version so a change invalidates the cache.

    If it did not, editing a prompt and rerunning would serve the old answers from
    results.jsonl and the run would silently report pre-edit behaviour.
    """
    t = _task()
    base = task_id(t, "model-a", "v1")
    assert task_id(t, "model-b", "v1") != base
    assert task_id(t, "model-a", "v2") != base
    assert task_id(t, "model-a", "v1") == base       # deterministic


def test_task_id_is_independent_of_slice_order():
    """Routing order is an implementation detail; the same work needs one id."""
    a = Slice(repo="r1", path="A.sol", contract="A", function="f",
              start_line=1, end_line=2, source="a")
    b = Slice(repo="r1", path="A.sol", contract="A", function="g",
              start_line=9, end_line=10, source="b")
    det = Detector(id="d", name="D", source_workflow="w", tags=["DoS"],
                   routing_hints=["f"], prompt_chars=1)
    t1 = Task(detector=det, path="A.sol", slices=[a, b])
    t2 = Task(detector=det, path="A.sol", slices=[b, a])
    assert task_id(t1, "m", "v1") == task_id(t2, "m", "v1")


def test_manifest_preserves_created_at_across_resume(tmp_path):
    store = RunStore(tmp_path / "run")
    store.write_manifest({"arm": "routed"})
    first = store.read_manifest()["created_at"]
    store.write_manifest({"arm": "routed", "resumed": True})
    assert store.read_manifest()["created_at"] == first
    assert store.read_manifest()["resumed"] is True
