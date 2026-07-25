from __future__ import annotations

import json
from pathlib import Path

import pytest

from bastet_cc.automation.budget import BudgetAuthority, Reservation
from bastet_cc.automation.contracts import (
    AIS3_BASE_URL,
    AIS3_PINNED_MODEL,
    BudgetExceeded,
    BudgetLimits,
    ConfigurationMismatch,
    GatewayProfile,
    GatewayRequest,
    ModelMismatch,
    ProviderPermanentError,
    ProviderResult,
    ProviderTransientError,
    Usage,
    sha256_text,
)
from bastet_cc.automation.gateway import Gateway
from bastet_cc.automation.ledger import Ledger, ensure_manifest
from bastet_cc.automation.provider import AIS3Provider, MockProvider


def _profile(**overrides) -> GatewayProfile:
    data = {
        "experiment_id": "exp-01",
        "subject_id": "subject-01",
        "provider_mode": "mock",
        "selected_workflow": "flashloan",
        "workflow_sha256": "a" * 64,
        "prompt_sha256": "b" * 64,
        "budget": BudgetLimits(
            global_calls=10,
            global_tokens=1_000,
            per_arm_calls=5,
            per_arm_tokens=600,
        ),
    }
    data.update(overrides)
    return GatewayProfile(**data)


def _request(**overrides) -> GatewayRequest:
    data = {
        "request_id": "req-01",
        "experiment_id": "exp-01",
        "subject_id": "subject-01",
        "surface": "openai",
        "arm": "bastet-cc",
        "stage": "detect",
        "messages": (
            {
                "role": "user",
                "content": (
                    "FILE Vault.sol | CONTRACT Vault | FUNCTION withdraw | L10-L12\n"
                    "check this function"
                ),
            },
        ),
        "requested_model": AIS3_PINNED_MODEL,
        "max_tokens": 256,
        "temperature": 0.0,
    }
    data.update(overrides)
    return GatewayRequest(**data)


class RecordingBudget:
    def __init__(self, *, deny: Exception | None = None) -> None:
        self.deny = deny
        self.reservations: list[tuple[str, int]] = []
        self.settlements: list[tuple[Reservation, Usage | None]] = []

    def reserve(self, arm: str, estimated_tokens: int) -> Reservation:
        self.reservations.append((arm, estimated_tokens))
        if self.deny is not None:
            raise self.deny
        return Reservation(
            reservation_id=f"reservation-{len(self.reservations)}",
            arm=arm,
            estimated_tokens=estimated_tokens,
        )

    def settle(self, reservation: Reservation, usage: Usage | None) -> None:
        self.settlements.append((reservation, usage))

    def snapshot(self) -> dict[str, int]:
        return {"reservations": len(self.reservations), "settlements": len(self.settlements)}


class RecordingLedger:
    def __init__(self) -> None:
        self.records: list[dict[str, object]] = []

    def append(self, record: dict[str, object]) -> None:
        self.records.append(record)

    def summary(self) -> dict[str, int]:
        return {"records": len(self.records)}


class SequenceProvider:
    def __init__(self, outcomes: list[object]) -> None:
        self.outcomes = list(outcomes)
        self.requests: list[GatewayRequest] = []
        self.closed = False

    def complete(self, request: GatewayRequest) -> ProviderResult:
        self.requests.append(request)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    def close(self) -> None:
        self.closed = True


class ReservationObservingProvider:
    def __init__(self, ledger: RecordingLedger) -> None:
        self.ledger = ledger

    def complete(self, _request: GatewayRequest) -> ProviderResult:
        assert self.ledger.records[-1]["event"] == "attempt_reserved"
        return ProviderResult("{}", Usage(input_tokens=4, output_tokens=2))

    def close(self) -> None:
        return


class StubResponse:
    def __init__(self, status_code: int, body: object) -> None:
        self.status_code = status_code
        self._body = body
        self.text = body if isinstance(body, str) else json.dumps(body)

    def json(self) -> object:
        if isinstance(self._body, Exception):
            raise self._body
        return self._body


class StubClient:
    def __init__(self, response: StubResponse | Exception) -> None:
        self.response = response
        self.calls: list[tuple[str, dict[str, object]]] = []
        self.closed = False

    def post(self, url: str, json: dict[str, object]) -> StubResponse:
        self.calls.append((url, json))
        if isinstance(self.response, Exception):
            raise self.response
        return self.response

    def close(self) -> None:
        self.closed = True


class TestBudgetAuthority:
    @pytest.mark.parametrize(
        ("limits", "prior", "arm", "estimated_tokens", "message"),
        [
            (
                BudgetLimits(global_calls=1, global_tokens=100, per_arm_calls=1, per_arm_tokens=100),
                [("upstream", 10)],
                "bastet-cc",
                5,
                "global call budget exceeded",
            ),
            (
                BudgetLimits(global_calls=5, global_tokens=10, per_arm_calls=5, per_arm_tokens=10),
                [("upstream", 8)],
                "bastet-cc",
                3,
                "global token budget exceeded",
            ),
            (
                BudgetLimits(global_calls=5, global_tokens=100, per_arm_calls=1, per_arm_tokens=100),
                [("bastet-cc", 10)],
                "bastet-cc",
                5,
                "bastet-cc call budget exceeded",
            ),
            (
                BudgetLimits(global_calls=5, global_tokens=100, per_arm_calls=5, per_arm_tokens=10),
                [("bastet-cc", 8)],
                "bastet-cc",
                3,
                "bastet-cc token budget exceeded",
            ),
        ],
    )
    def test_reserve_denial_is_atomic_for_all_budget_axes(
        self,
        limits: BudgetLimits,
        prior: list[tuple[str, int]],
        arm: str,
        estimated_tokens: int,
        message: str,
    ) -> None:
        authority = BudgetAuthority(limits)
        for prior_arm, prior_tokens in prior:
            authority.reserve(prior_arm, prior_tokens)

        before = authority.snapshot()

        with pytest.raises(BudgetExceeded, match=message):
            authority.reserve(arm, estimated_tokens)

        assert authority.snapshot() == before

    def test_settle_reconciles_actual_usage_and_clears_in_flight(self) -> None:
        authority = BudgetAuthority(
            BudgetLimits(global_calls=5, global_tokens=100, per_arm_calls=5, per_arm_tokens=100)
        )
        reservation = authority.reserve("bastet-cc", 20)

        authority.settle(reservation, Usage(input_tokens=7, output_tokens=24))

        snapshot = authority.snapshot()
        assert snapshot["global"] == {"calls": 1, "tokens": 31}
        assert snapshot["arms"]["bastet-cc"] == {"calls": 1, "tokens": 31}
        assert snapshot["in_flight"] == []

    def test_settle_rejects_double_settlement(self) -> None:
        authority = BudgetAuthority(
            BudgetLimits(global_calls=5, global_tokens=100, per_arm_calls=5, per_arm_tokens=100)
        )
        reservation = authority.reserve("upstream", 12)
        authority.settle(reservation, Usage(input_tokens=5, output_tokens=6))

        with pytest.raises(ValueError, match="reservation already settled"):
            authority.settle(reservation, Usage(input_tokens=1, output_tokens=1))

    def test_settle_fails_closed_when_reported_usage_exceeds_token_limit(self) -> None:
        authority = BudgetAuthority(
            BudgetLimits(
                global_calls=2,
                global_tokens=10,
                per_arm_calls=2,
                per_arm_tokens=10,
            )
        )
        reservation = authority.reserve("bastet-cc", 1)

        with pytest.raises(BudgetExceeded, match="settled token budget exceeded"):
            authority.settle(reservation, Usage(input_tokens=6, output_tokens=5))

        snapshot = authority.snapshot()
        assert snapshot["global"] == {"calls": 1, "tokens": 10}
        assert snapshot["arms"]["bastet-cc"] == {"calls": 1, "tokens": 10}
        assert snapshot["in_flight"] == []

    def test_settle_rejects_foreign_reservation_without_mutation(self) -> None:
        local = BudgetAuthority(
            BudgetLimits(global_calls=5, global_tokens=100, per_arm_calls=5, per_arm_tokens=100)
        )
        foreign = BudgetAuthority(
            BudgetLimits(global_calls=5, global_tokens=100, per_arm_calls=5, per_arm_tokens=100)
        )
        reservation = foreign.reserve("upstream", 9)
        before = local.snapshot()

        with pytest.raises(ValueError, match="unknown reservation"):
            local.settle(reservation, Usage(input_tokens=3, output_tokens=2))

        assert local.snapshot() == before

    def test_restore_charges_an_unsettled_durable_reservation_fail_closed(self) -> None:
        limits = BudgetLimits(
            global_calls=1,
            global_tokens=100,
            per_arm_calls=1,
            per_arm_tokens=100,
        )
        authority = BudgetAuthority(
            limits,
            prior_records=[
                {
                    "event": "attempt_reserved",
                    "reservation_id": "reservation-crash",
                    "arm": "bastet-cc",
                    "calls": 1,
                    "tokens": 80,
                    "reserved_tokens": 80,
                }
            ],
        )

        snapshot = authority.snapshot()
        assert snapshot["global"] == {"calls": 1, "tokens": 80}
        assert snapshot["recovered_pending"] == [
            {
                "reservation_id": "reservation-crash",
                "arm": "bastet-cc",
                "estimated_tokens": 80,
            }
        ]
        with pytest.raises(BudgetExceeded, match="global call budget exceeded"):
            authority.reserve("upstream", 1)

    def test_restore_reconciles_a_settled_wal_pair_to_actual_usage(self) -> None:
        authority = BudgetAuthority(
            BudgetLimits(
                global_calls=2,
                global_tokens=100,
                per_arm_calls=2,
                per_arm_tokens=100,
            ),
            prior_records=[
                {
                    "event": "attempt_reserved",
                    "reservation_id": "reservation-settled",
                    "arm": "upstream",
                    "calls": 1,
                    "tokens": 80,
                    "reserved_tokens": 80,
                },
                {
                    "event": "attempt_settled",
                    "reservation_id": "reservation-settled",
                    "arm": "upstream",
                    "calls": 0,
                    "tokens": -60,
                    "reserved_tokens": 80,
                    "charged_tokens": 20,
                },
            ],
        )

        snapshot = authority.snapshot()
        assert snapshot["global"] == {"calls": 1, "tokens": 20}
        assert snapshot["arms"]["upstream"] == {"calls": 1, "tokens": 20}
        assert snapshot["recovered_pending"] == []

    def test_restore_replays_a_budget_exceeded_settlement_at_the_ceiling(self) -> None:
        authority = BudgetAuthority(
            BudgetLimits(
                global_calls=2,
                global_tokens=10,
                per_arm_calls=2,
                per_arm_tokens=10,
            ),
            prior_records=[
                {
                    "event": "attempt_reserved",
                    "reservation_id": "reservation-overage",
                    "arm": "bastet-cc",
                    "calls": 1,
                    "tokens": 1,
                    "reserved_tokens": 1,
                },
                {
                    "event": "attempt_settled",
                    "reservation_id": "reservation-overage",
                    "arm": "bastet-cc",
                    "status": "settled_budget_exceeded",
                    "calls": 0,
                    "tokens": 10,
                    "reserved_tokens": 1,
                    "charged_tokens": 11,
                },
            ],
        )

        snapshot = authority.snapshot()
        assert snapshot["global"] == {"calls": 1, "tokens": 10}
        assert snapshot["arms"]["bastet-cc"] == {"calls": 1, "tokens": 10}


class TestLedger:
    def test_append_redacts_nested_secrets_and_omits_prompt_bodies(self, tmp_path: Path) -> None:
        ledger = Ledger(tmp_path / "ledger.jsonl")
        fake_key = "sk-" + "live-not-real"
        sensitive_key = "api" + "_key"
        ledger.append(
            {
                "status": "ok",
                "prompt": "secret prompt body",
                "messages": [{"role": "user", "content": "should disappear"}],
                "payload": {
                    "Authorization": ("Bear" + "er ") + fake_key,
                    "nested": [{sensitive_key: "sk-" + "example-not-real"}],
                },
            }
        )

        [record] = ledger.records()
        assert record["prompt"] == "[OMITTED]"
        assert record["messages"] == "[OMITTED]"
        assert record["payload"]["Authorization"] == "[REDACTED]"
        assert record["payload"]["nested"][0]["api_key"] == "[REDACTED]"
        assert "secret prompt body" not in json.dumps(record, sort_keys=True)
        assert "should disappear" not in json.dumps(record, sort_keys=True)

    @pytest.mark.parametrize("contents", ["{not-json\n", "[]\n"])
    def test_records_fail_closed_on_malformed_or_non_object_lines(
        self, tmp_path: Path, contents: str
    ) -> None:
        path = tmp_path / "ledger.jsonl"
        path.write_text(contents, encoding="utf-8")

        with pytest.raises(ConfigurationMismatch, match="ledger line 1"):
            Ledger(path).records()

    @pytest.mark.parametrize(
        "manifest_data",
        [
            lambda profile: {**profile.manifest(), "subject_id": "subject-02", "fingerprint": "1" * 64},
            lambda profile: {**profile.manifest(), "model": "ais3/other-model", "fingerprint": "2" * 64},
            lambda profile: {
                **profile.manifest(),
                "budget": {
                    "global_calls": 999,
                    "global_tokens": 1_000,
                    "per_arm_calls": 5,
                    "per_arm_tokens": 600,
                },
                "fingerprint": "3" * 64,
            },
            lambda profile: {**profile.manifest(), "fingerprint": "0" * 64},
        ],
    )
    def test_ensure_manifest_rejects_immutable_manifest_mismatch(
        self, tmp_path: Path, manifest_data
    ) -> None:
        profile = _profile()
        manifest_path = tmp_path / "manifest.json"
        ensure_manifest(manifest_path, profile)
        existing = manifest_data(profile)
        manifest_path.write_text(json.dumps(existing, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        with pytest.raises(ConfigurationMismatch, match="fingerprint differs"):
            ensure_manifest(manifest_path, profile)


class TestGatewayValidation:
    @pytest.mark.parametrize(
        ("changes", "error_type", "message"),
        [
            ({"surface": "n8n", "arm": "bastet-cc"}, ConfigurationMismatch, "must use arm 'upstream'"),
            ({"surface": "openai", "arm": "upstream"}, ConfigurationMismatch, "must use arm 'bastet-cc'"),
            ({"surface": "cli"}, ConfigurationMismatch, "unsupported surface"),
            ({"requested_model": "ais3/not-pinned"}, ModelMismatch, "model must be pinned"),
            ({"experiment_id": "exp-02"}, ConfigurationMismatch, "experiment_id does not match"),
            ({"subject_id": "subject-02"}, ConfigurationMismatch, "subject_id does not match"),
        ],
    )
    def test_complete_rejects_mismatched_surface_arm_model_experiment_and_subject(
        self,
        changes: dict[str, object],
        error_type: type[Exception],
        message: str,
    ) -> None:
        gateway = Gateway(_profile(), RecordingBudget(), RecordingLedger(), MockProvider())

        with pytest.raises(error_type, match=message):
            gateway.complete(_request(**changes))

    def test_schema_version_is_part_of_the_context_namespace(self) -> None:
        first = _request(schema_kind="schema-v1")
        second = _request(schema_kind="schema-v2")

        assert first.context_namespace != second.context_namespace
        assert sha256_text(first.context_namespace) != sha256_text(second.context_namespace)

    @pytest.mark.parametrize(
        "changes",
        [
            {"stage": "arbitrary"},
            {"experiment_id": "experiment-" + ("a" * 40)},
            {"subject_id": "subject-sk_" + ("A" * 20)},
        ],
    )
    def test_request_rejects_unbounded_stage_and_credential_shaped_ids(
        self, changes: dict[str, object]
    ) -> None:
        with pytest.raises(ValueError):
            _request(**changes)


class TestGatewayExecution:
    def test_transient_retries_reserve_settle_and_ledger_once_per_attempt(self) -> None:
        budget = RecordingBudget()
        ledger = RecordingLedger()
        sleeps: list[float] = []
        provider = SequenceProvider(
            [
                ProviderTransientError("first"),
                ProviderTransientError("second"),
                ProviderResult("{}", Usage(input_tokens=9, output_tokens=4)),
            ]
        )
        gateway = Gateway(
            _profile(),
            budget,
            ledger,
            provider,
            max_attempts=3,
            sleep_fn=sleeps.append,
        )

        result = gateway.complete(_request())

        assert result.provider_attempts == 3
        assert len(provider.requests) == 3
        assert len(budget.reservations) == 3
        assert len(budget.settlements) == 3
        assert [record["event"] for record in ledger.records] == [
            "attempt_reserved",
            "attempt_settled",
            "attempt_reserved",
            "attempt_settled",
            "attempt_reserved",
            "attempt_settled",
        ]
        assert [
            record["status"]
            for record in ledger.records
            if record["event"] == "attempt_settled"
        ] == ["transient_error", "transient_error", "ok"]
        assert [record["attempt"] for record in ledger.records] == [1, 1, 2, 2, 3, 3]
        assert sleeps == [2.0, 8.0]
        request = _request()
        assert budget.reservations == [
            ("bastet-cc", request.estimated_input_tokens + request.max_tokens)
        ] * 3

    def test_permanent_error_is_not_retried(self) -> None:
        budget = RecordingBudget()
        ledger = RecordingLedger()
        provider = SequenceProvider([ProviderPermanentError("bad request")])
        gateway = Gateway(
            _profile(),
            budget,
            ledger,
            provider,
            max_attempts=3,
            sleep_fn=lambda _: pytest.fail("sleep should not run on permanent error"),
        )

        with pytest.raises(ProviderPermanentError, match="bad request"):
            gateway.complete(_request())

        assert len(provider.requests) == 1
        assert len(budget.reservations) == 1
        assert len(budget.settlements) == 1
        assert [record["status"] for record in ledger.records] == [
            "reserved",
            "permanent_error",
        ]

    def test_budget_denial_does_not_invoke_provider(self) -> None:
        budget = RecordingBudget(deny=BudgetExceeded("no tokens left"))
        ledger = RecordingLedger()
        provider = SequenceProvider([ProviderResult("{}", Usage(input_tokens=1, output_tokens=1))])
        gateway = Gateway(_profile(), budget, ledger, provider)

        with pytest.raises(BudgetExceeded, match="no tokens left"):
            gateway.complete(_request())

        assert provider.requests == []
        assert budget.settlements == []
        assert len(ledger.records) == 1
        assert ledger.records[0]["status"] == "budget_denied"

    def test_reservation_is_durable_before_the_provider_is_invoked(self) -> None:
        budget = RecordingBudget()
        ledger = RecordingLedger()
        gateway = Gateway(
            _profile(),
            budget,
            ledger,
            ReservationObservingProvider(ledger),
        )

        gateway.complete(_request())

        assert [record["event"] for record in ledger.records] == [
            "attempt_reserved",
            "attempt_settled",
        ]


class TestProviders:
    @pytest.mark.parametrize(
        ("surface", "arm", "stage"),
        [
            ("openai", "bastet-cc", "detect"),
            ("n8n", "upstream", "scan"),
        ],
    )
    def test_mock_provider_is_deterministic_for_both_surface_schemas(
        self, surface: str, arm: str, stage: str
    ) -> None:
        provider = MockProvider()
        request = _request(surface=surface, arm=arm, stage=stage)

        first = provider.complete(request)
        second = provider.complete(request)

        assert first == second
        payload = json.loads(first.text)
        if surface == "openai":
            assert list(payload) == ["findings"]
            assert payload["findings"][0]["severity"] in {"High", "Medium", "Low"}
        else:
            assert isinstance(payload, list)
            assert payload[0]["severity"] in {"high", "medium", "low"}
            assert "vulnerability_details" in payload[0]

    @pytest.mark.parametrize(
        ("kwargs", "message"),
        [
            ({"endpoint": "https://example.com/v1"}, "endpoint must be pinned"),
            ({"model": "ais3/not-pinned"}, "model must be pinned"),
        ],
    )
    def test_ais3_provider_rejects_alternate_endpoint_and_model(
        self, kwargs: dict[str, object], message: str
    ) -> None:
        with pytest.raises(ValueError, match=message):
            AIS3Provider("fake-key", **kwargs)

    def test_ais3_provider_omits_remote_body_from_http_errors(self) -> None:
        fake_key = "sk-" + "live-should-not-appear"
        remote_body = {
            "error": {
                "message": ("api" + "_key ") + fake_key + " request failed",
                "details": {"prompt": "user secret"},
            }
        }
        client = StubClient(StubResponse(400, remote_body))
        provider = AIS3Provider("fake-key", client=client)

        with pytest.raises(ProviderPermanentError, match=r"HTTP 400") as excinfo:
            provider.complete(_request())

        message = str(excinfo.value)
        assert fake_key not in message
        assert "user secret" not in message
        assert "provider rejected request (HTTP 400)" == message
        assert client.calls[0][0] == f"{AIS3_BASE_URL}/chat/completions"
