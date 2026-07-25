"""Routing's IDF cut, the broadcast arm's fidelity, and one-hop call closure.

The routing tests guard a recall property: a detector must never go dark
silently. The plan tests guard the experiment: nothing may make the broadcast
control arm cheaper or smarter, because every cost and accuracy claim is
measured against it.
"""

from __future__ import annotations

import pytest

from bastet_cc.callgraph import (CallIndex, MAX_CALLEES, closure_for, expand_slice,
                                 expand_tasks, render_closure)
from bastet_cc.plan import plan, last_closure_stats
from bastet_cc.routing import (Detector, MAX_DOC_FREQ, MIN_HINTS, broadcast_cost,
                               cost, fit, route, slices_from_index)


class TestFit:
    def test_ubiquitous_hints_are_dropped(self, repo_index, detectors):
        # "a" appears in every function of the fixture, so its document
        # frequency is 1.0 and it carries no routing information.
        fit(detectors, [repo_index])
        generic = next(d for d in detectors if d.id == "d_generic")
        assert generic.signature == set()

    def test_detector_left_without_hints_broadcasts_rather_than_going_dark(
            self, repo_index, detectors):
        fit(detectors, [repo_index])
        generic = next(d for d in detectors if d.id == "d_generic")
        assert generic.broadcast is True
        tasks = route(detectors, repo_index)
        assert any(t.detector.id == "d_generic" for t in tasks), \
            "a detector with no usable signature must broadcast, not vanish"

    def test_rare_hints_survive(self, repo_index, detectors):
        fit(detectors, [repo_index])
        swap = next(d for d in detectors if d.id == "d_swap")
        assert "_payout" in swap.signature
        assert swap.broadcast is False

    def test_hints_absent_from_the_corpus_are_kept(self, repo_index):
        # df == 0 means maximally specific, not useless: the correct behaviour
        # is to keep the hint and simply not route here.
        d = Detector(id="x", name="x", source_workflow="w", tags=["T"],
                     routing_hints=["neverAppearsAnywhere", "alsoAbsent"],
                     prompt_chars=10)
        fit([d], [repo_index])
        assert d.signature == {"neverAppearsAnywhere", "alsoAbsent"}
        assert route([d], repo_index) == []

    def test_empty_corpus_makes_everything_broadcast(self, detectors):
        stats = fit(detectors, [])
        assert stats["n_functions"] == 0
        assert all(d.broadcast for d in detectors)

    def test_thresholds_are_the_documented_ones(self):
        assert MAX_DOC_FREQ == 0.15
        assert MIN_HINTS == 2


class TestRoutePlan:
    def test_one_task_per_detector_file_pair(self, repo_index, detectors):
        fit(detectors, [repo_index])
        tasks = route(detectors, repo_index)
        pairs = [(t.detector.id, t.path) for t in tasks]
        assert len(pairs) == len(set(pairs)), "batching is per (detector, file)"

    def test_routed_never_costs_more_calls_than_broadcast(self, repo_index, detectors):
        fit(detectors, [repo_index])
        routed = cost(route(detectors, repo_index))
        bcast = broadcast_cost(detectors, repo_index)
        assert routed["calls"] <= bcast["calls"]

    def test_slices_from_index_covers_every_function(self, repo_index):
        assert len(slices_from_index(repo_index)) == repo_index["n_functions"]


class TestBroadcastArmIsNotHelped:
    def test_closure_is_refused_on_the_control_arm(self, tmp_path, detectors):
        (tmp_path / "A.sol").write_text("contract A { function f() public {} }")
        with pytest.raises(ValueError, match="routed-arm treatment"):
            plan("broadcast", detectors, tmp_path, closure=True)

    def test_broadcast_takes_every_sol_file_including_vendor(self, tmp_path, detectors):
        (tmp_path / "A.sol").write_text("contract A {}")
        vendor = tmp_path / "node_modules" / "oz"
        vendor.mkdir(parents=True)
        (vendor / "B.sol").write_text("contract B {}")
        tests = tmp_path / "test"
        tests.mkdir()
        (tests / "C.t.sol").write_text("contract C {}")

        tasks = plan("broadcast", detectors, tmp_path)
        paths = {t.path for t in tasks}
        assert paths == {"A.sol", "node_modules/oz/B.sol", "test/C.t.sol"}, \
            "upstream globs **/*.sol with no filtering; the control must too"

    def test_routed_plan_requires_fit_first(self, tmp_path, detectors, repo_index):
        with pytest.raises(ValueError, match="routing.fit"):
            plan("routed", detectors, tmp_path, repo_index=repo_index)


class TestCallClosure:
    def test_resolves_direct_callees_only(self, repo_index):
        index = CallIndex(repo_index)
        withdraw = next(s for s in slices_from_index(repo_index)
                        if s.function == "withdraw")
        idents = {"withdraw", "_burn", "_payout", "a", "uint"}
        refs, stats = closure_for(withdraw, idents, index)
        names = {r.name for r in refs}
        assert names == {"_burn", "_payout"}
        assert "safeTransfer" not in names, "two-hop callees must not be pulled in"
        assert stats["resolved"] == 2

    def test_self_reference_is_excluded(self, repo_index):
        index = CallIndex(repo_index)
        payout = next(s for s in slices_from_index(repo_index)
                      if s.function == "_payout")
        refs, _ = closure_for(payout, {"_payout", "safeTransfer"}, index)
        assert {r.name for r in refs} == {"safeTransfer"}

    def test_builtins_are_not_looked_up(self, repo_index):
        index = CallIndex(repo_index)
        sl = next(s for s in slices_from_index(repo_index) if s.function == "withdraw")
        refs, stats = closure_for(sl, {"require", "keccak256", "msg", "revert"}, index)
        assert refs == []
        assert stats["candidates"] == 0

    def test_fan_out_cap_is_enforced(self, repo_index):
        index = CallIndex(repo_index)
        sl = next(s for s in slices_from_index(repo_index) if s.function == "withdraw")
        refs, stats = closure_for(sl, {"_burn", "_payout"}, index, max_callees=1)
        assert len(refs) == 1
        assert stats["truncated_by"] == "fan_out"

    def test_char_cap_is_enforced(self, repo_index):
        index = CallIndex(repo_index)
        sl = next(s for s in slices_from_index(repo_index) if s.function == "withdraw")
        refs, stats = closure_for(sl, {"_burn", "_payout"}, index, max_chars=1)
        assert refs == []
        assert stats["truncated_by"] == "chars"

    def test_expansion_preserves_slice_identity(self, repo_index):
        # task_id folds in slice.id; if closure changed it, resume would treat
        # every task as new and the ablation could not share a cache boundary.
        index = CallIndex(repo_index)
        sl = next(s for s in slices_from_index(repo_index) if s.function == "withdraw")
        expanded, _ = expand_slice(sl, {"_burn", "_payout"}, index)
        assert expanded.id == sl.id
        assert len(expanded.source) > len(sl.source)

    def test_closure_block_is_labelled_as_context(self, repo_index):
        index = CallIndex(repo_index)
        sl = next(s for s in slices_from_index(repo_index) if s.function == "withdraw")
        refs, _ = closure_for(sl, {"_burn"}, index)
        block = render_closure(refs)
        assert "CONTEXT ONLY" in block
        assert "Do NOT report findings against these" in block

    def test_resolution_is_deterministic(self, repo_index):
        index = CallIndex(repo_index)
        sl = next(s for s in slices_from_index(repo_index) if s.function == "withdraw")
        runs = [[r.name for r in closure_for(sl, {"_burn", "_payout"}, index)[0]]
                for _ in range(5)]
        assert len(set(map(tuple, runs))) == 1, "identifiers is a set; order must be forced"

    def test_same_contract_definition_wins_over_a_namesake(self):
        def fn(name, contract, start, src):
            return {"name": name, "kind": "function", "contract": contract,
                    "visibility": "internal", "modifiers": [], "params": "()",
                    "start_line": start, "end_line": start + 1, "source": src,
                    "identifiers": [name]}
        ix = {"repo": "r", "files": [
            {"path": "A.sol", "contracts": ["A"], "imports": [], "n_bytes": 1,
             "parse_errors": 0, "functions": [fn("helper", "A", 1, "// A.helper")]},
            {"path": "B.sol", "contracts": ["B"], "imports": [], "n_bytes": 1,
             "parse_errors": 0, "functions": [fn("helper", "B", 1, "// B.helper")]},
        ]}
        index = CallIndex(ix)
        assert [r.source for r in index.resolve("B", "helper")] == ["// B.helper"]

    def test_expand_tasks_reports_what_it_spent(self, repo_index, detectors):
        fit(detectors, [repo_index])
        tasks = route(detectors, repo_index)
        stats = expand_tasks(tasks, repo_index)
        assert stats["slices"] > 0
        assert 0.0 <= stats["expansion_rate"] <= 1.0
        assert stats["added_tokens_est"] == stats["added_chars"] // 4

    def test_plan_records_closure_cost(self, tmp_path, repo_index, detectors):
        fit(detectors, [repo_index])
        plan("routed", detectors, tmp_path, repo_index=repo_index, closure=True)
        stats = last_closure_stats()
        assert stats and stats["max_callees"] == MAX_CALLEES

    def test_closure_changes_payload_not_the_call_count(self, tmp_path, repo_index,
                                                        detectors):
        # The whole point of the ablation: same routing decision, bigger payload.
        fit(detectors, [repo_index])
        plain = plan("routed", detectors, tmp_path, repo_index=repo_index)
        fit(detectors, [repo_index])
        closed = plan("routed", detectors, tmp_path, repo_index=repo_index, closure=True)
        assert len(plain) == len(closed)
        assert cost(closed)["input_tokens"] >= cost(plain)["input_tokens"]
