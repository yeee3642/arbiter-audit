from __future__ import annotations

from bastet_cc.twincourt import adjudication_id, normalize_decision


def test_confirmed_requires_causal_path_and_valid_fragment(finding_factory):
    parsed = {
        "verdict": "confirmed",
        "reason_code": "exploit_path_proven",
        "preconditions": ["attacker controls callback"],
        "causal_steps": ["entry calls helper", "helper transfers before state update"],
        "counter_evidence": [],
        "cited_fragment_ids": ["hfx-target", "invented"],
        "summary": "Concrete path.",
    }
    decision = normalize_decision(parsed, {"hfx-target"})
    assert decision.verdict == "confirmed"
    assert decision.cited_fragment_ids == ("hfx-target",)

    parsed["cited_fragment_ids"] = ["invented"]
    downgraded = normalize_decision(parsed, {"hfx-target"})
    assert downgraded.verdict == "uncertain"
    assert downgraded.gate_reason == "confirmation_missing_causal_evidence"


def test_rejected_requires_cited_counter_evidence():
    parsed = {
        "verdict": "rejected",
        "reason_code": "guarded",
        "preconditions": [],
        "causal_steps": [],
        "counter_evidence": ["nonReentrant blocks the callback"],
        "cited_fragment_ids": ["hfx-modifier"],
        "summary": "Guarded.",
    }
    assert normalize_decision(parsed, {"hfx-modifier"}).verdict == "rejected"
    parsed["counter_evidence"] = []
    assert normalize_decision(parsed, {"hfx-modifier"}).verdict == "uncertain"


def test_malformed_or_unsupported_payload_fails_closed():
    malformed = normalize_decision("not-an-object", set())
    assert malformed.verdict == "uncertain"
    assert malformed.gate_reason == "malformed_response"

    unsupported = normalize_decision({
        "verdict": "definitely",
        "reason_code": "because",
        "summary": "x",
    }, set())
    assert unsupported.verdict == "uncertain"
    assert unsupported.reason_code == "invalid_claim"


def test_cache_identity_covers_profile_packet_and_budget(finding_factory):
    finding = finding_factory(description="same claim")
    base = dict(
        model="ais3/llama-3.1-8b",
        provider_fingerprint="profile-a",
        packet_id="packet-a",
        hermes_version="hermes-v1",
        hermes_config={"total_chars": 24000},
    )
    first = adjudication_id(finding, **base)
    assert adjudication_id(finding, **base) == first
    for field, value in (
        ("model", "other"),
        ("provider_fingerprint", "profile-b"),
        ("packet_id", "packet-b"),
        ("hermes_version", "hermes-v2"),
        ("hermes_config", {"total_chars": 12000}),
    ):
        changed = dict(base)
        changed[field] = value
        assert adjudication_id(finding, **changed) != first
    assert first.startswith("court-")


def test_model_lists_are_bounded_and_normalized():
    parsed = {
        "verdict": "uncertain",
        "reason_code": "insufficient_context",
        "preconditions": [f"  p {i}  " for i in range(20)],
        "causal_steps": [],
        "counter_evidence": [],
        "cited_fragment_ids": [],
        "summary": "  spaced   summary ",
    }
    decision = normalize_decision(parsed, set())
    assert len(decision.preconditions) == 12
    assert decision.preconditions[0] == "p 0"
    assert decision.summary == "spaced summary"
