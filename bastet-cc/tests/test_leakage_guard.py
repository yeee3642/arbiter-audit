"""The leakage rule must be able to fail.

The original Rule 1 grepped synthesised detector prompts for 12-hex repository
hashes. The synthesiser never writes them, so the grep matched nothing across all
23 detectors and the rule reported PASS without ever inspecting anything. That is
worse than having no check: it produced an artefact
(`runs/leakage_audit.json: {"status": "PASS"}`) asserting the most leak-prone
stage in the pipeline was clean.

So the tests here are adversarial by construction. Each plants a detector that
*is* contaminated and asserts the audit says so. A rule that cannot be made to
fail is not tested by a passing corpus.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load_audit_module():
    spec = importlib.util.spec_from_file_location(
        "leakage_audit_under_test", ROOT / "scripts" / "leakage_audit.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def audit():
    return _load_audit_module()


@pytest.fixture
def splits():
    return {
        "train_syn": {"aaaaaaaaaaaa", "bbbbbbbbbbbb"},
        "dev": {"cccccccccccc"},
        "test": {"dddddddddddd"},
    }


def _detector_md(provenance: dict | None, body: str = "some prompt text") -> str:
    front = ["---", "id: synth__x", 'name: "X"', "tags: [\"T\"]"]
    if provenance is not None:
        front.append(f"synth_provenance: {json.dumps(provenance)}")
    front.append("---")
    return "\n".join(front) + "\n\n" + body


class TestProvenanceExtraction:
    def test_front_matter_ids_are_preferred(self, audit):
        md = _detector_md({"train_findings": ["7", "12"], "mode": "s2"})
        ids, source = audit._provenance_repos(md)
        assert source == "front_matter_finding_ids"
        assert ids == {"7", "12"}

    def test_falls_back_to_hash_grep_when_no_provenance(self, audit):
        md = _detector_md(None, body="mentions aaaaaaaaaaaa directly")
        ids, source = audit._provenance_repos(md)
        assert source == "hash_grep_fallback"
        assert ids == {"aaaaaaaaaaaa"}

    def test_empty_finding_list_is_not_treated_as_provenance(self, audit):
        # An empty list must not read as "verified clean" -- it is the absence
        # of evidence, and that is what the vacuity bug was.
        md = _detector_md({"train_findings": [], "mode": "s2"})
        _, source = audit._provenance_repos(md)
        assert source == "hash_grep_fallback"

    def test_s2b_is_its_own_category_not_a_leak(self, audit):
        # S2b induces from the tag definition alone, for tags with zero
        # TRAIN-SYN positives. No label was read, so calling it a leak would be
        # wrong -- but it is not evidence-backed either.
        md = _detector_md({"train_findings": [], "mode": "s2b"})
        ids, source = audit._provenance_repos(md)
        assert source == "no_training_material"
        assert ids == set()

    def test_real_s2b_detectors_are_classified_that_way(self, audit):
        # The three shipped S2b detectors target Compound / EIP4494 /
        # Solidity Version, whose only positive repository is in TEST.
        synth = ROOT / "detectors_synth"
        if not synth.is_dir():
            pytest.skip("detectors_synth not built")
        modes = {}
        for md in synth.glob("*.md"):
            _, source = audit._provenance_repos(md.read_text(encoding="utf-8"))
            modes[md.stem] = source
        s2b = {k for k, v in modes.items() if v == "no_training_material"}
        assert s2b == {"synth__compound", "synth__eip4494",
                       "synth__solidity_version"}, s2b
        assert "hash_grep_fallback" not in modes.values(), \
            "every shipped detector must expose machine-readable provenance"

    def test_malformed_provenance_json_degrades_rather_than_crashes(self, audit):
        md = "---\nsynth_provenance: {not valid json}\n---\nbody\n"
        ids, source = audit._provenance_repos(md)
        assert source == "hash_grep_fallback"
        assert ids == set()


class TestRuleOneCanFail:
    def _run(self, audit, tmp_path, monkeypatch, splits, md_files, id2repo):
        synth = tmp_path / "detectors_synth"
        synth.mkdir()
        for name, text in md_files.items():
            (synth / name).write_text(text, encoding="utf-8")
        monkeypatch.setattr(audit, "PKG", tmp_path)
        monkeypatch.setattr(audit, "_finding_id_to_repo", lambda: id2repo)
        return audit.audit_detectors(splits)

    def test_detects_a_detector_induced_from_dev(self, audit, tmp_path,
                                                 monkeypatch, splits):
        rows = self._run(
            audit, tmp_path, monkeypatch, splits,
            {"synth__leaky.md": _detector_md({"train_findings": ["1", "2"]})},
            {"1": "aaaaaaaaaaaa", "2": "cccccccccccc"})     # 2 -> DEV
        assert rows[0]["from_dev"] == ["cccccccccccc"]
        assert rows[0]["from_train_syn"] == 1

    def test_detects_a_detector_induced_from_test(self, audit, tmp_path,
                                                  monkeypatch, splits):
        rows = self._run(
            audit, tmp_path, monkeypatch, splits,
            {"synth__leaky.md": _detector_md({"train_findings": ["9"]})},
            {"9": "dddddddddddd"})                           # TEST
        assert rows[0]["from_test"] == ["dddddddddddd"]

    def test_clean_detector_passes(self, audit, tmp_path, monkeypatch, splits):
        rows = self._run(
            audit, tmp_path, monkeypatch, splits,
            {"synth__ok.md": _detector_md({"train_findings": ["1", "3"]})},
            {"1": "aaaaaaaaaaaa", "3": "bbbbbbbbbbbb"})
        assert rows[0]["from_dev"] == [] and rows[0]["from_test"] == []
        assert rows[0]["from_train_syn"] == 2
        assert rows[0]["provenance_source"] == "front_matter_finding_ids"

    def test_provenance_free_detector_is_flagged_not_cleared(self, audit, tmp_path,
                                                             monkeypatch, splits):
        # The exact shape of the original bug: a prompt with no repo hashes in
        # it. It must report as unverifiable, never as clean.
        rows = self._run(audit, tmp_path, monkeypatch, splits,
                         {"synth__opaque.md": _detector_md(None)}, {})
        row = rows[0]
        assert row["provenance_source"] == "hash_grep_fallback"
        assert row["cited_repos"] == 0
        blind = (row["provenance_source"] != "front_matter_finding_ids"
                 or row["cited_repos"] == 0)
        assert blind, "a detector with no resolvable provenance must not count as clean"

    def test_unresolvable_ids_are_reported(self, audit, tmp_path, monkeypatch, splits):
        rows = self._run(
            audit, tmp_path, monkeypatch, splits,
            {"synth__x.md": _detector_md({"train_findings": ["1", "999"]})},
            {"1": "aaaaaaaaaaaa"})
        assert rows[0]["unresolved_ids"] == ["999"]


class TestFreezeVerification:
    def test_recomputes_the_recorded_digest(self, audit):
        import hashlib
        body = {"train_syn": ["aaaaaaaaaaaa"], "dev": [], "test": []}
        digest = hashlib.sha256(
            json.dumps(body, indent=2, sort_keys=True).encode()).hexdigest()
        assert audit.verify_freeze({**body, "splits_sha256": digest})

    def test_detects_a_post_freeze_edit(self, audit):
        import hashlib
        body = {"train_syn": ["aaaaaaaaaaaa"], "dev": [], "test": []}
        digest = hashlib.sha256(
            json.dumps(body, indent=2, sort_keys=True).encode()).hexdigest()
        tampered = {**body, "dev": ["cccccccccccc"], "splits_sha256": digest}
        assert not audit.verify_freeze(tampered)

    def test_missing_digest_is_not_frozen(self, audit):
        assert not audit.verify_freeze({"train_syn": [], "dev": [], "test": []})


class TestRealSplitsFileIsIntact:
    def test_shipped_splits_still_verify(self, audit):
        splits_path = ROOT.parent / "data" / "splits.json"
        if not splits_path.exists():
            pytest.skip("data/splits.json not present")
        payload = json.loads(splits_path.read_text())
        assert audit.verify_freeze(payload), \
            "splits.json was edited after the freeze; every measurement is void"

    def test_splits_do_not_overlap(self, audit):
        splits_path = ROOT.parent / "data" / "splits.json"
        if not splits_path.exists():
            pytest.skip("data/splits.json not present")
        p = json.loads(splits_path.read_text())
        s = {k: set(p[k]) for k in ("train_syn", "dev", "test")}
        assert not (s["train_syn"] & s["dev"])
        assert not (s["train_syn"] & s["test"])
        assert not (s["dev"] & s["test"])
        assert len(s["train_syn"] | s["dev"] | s["test"]) == p["n_repos"]
