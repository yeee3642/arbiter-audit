"""Thread-safe fair-use accounting for the automation gateway."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from threading import RLock
from typing import Any, Iterable, Mapping

from .contracts import (
    BudgetExceeded,
    BudgetLimits,
    ConfigurationMismatch,
    Usage,
    validate_identifier,
)

_ALLOWED_ARMS = frozenset({"upstream", "bastet-cc"})


@dataclass(frozen=True)
class Reservation:
    reservation_id: str
    arm: str
    estimated_tokens: int


class BudgetAuthority:
    """Reserve provider-call budget up front and reconcile usage on settlement."""

    def __init__(
        self,
        limits: BudgetLimits,
        prior_records: Iterable[Mapping[str, Any]] | None = None,
    ):
        self.limits = limits
        self._lock = RLock()
        self._global = {"calls": 0, "tokens": 0}
        self._arms = {
            arm: {"calls": 0, "tokens": 0}
            for arm in sorted(_ALLOWED_ARMS)
        }
        self._in_flight: dict[str, Reservation] = {}
        self._settled: set[str] = set()
        self._recovered_pending: dict[str, Reservation] = {}
        self._restore(prior_records or ())

    def reserve(self, arm: str, estimated_tokens: int) -> Reservation:
        arm_name = self._validate_arm(arm)
        tokens = self._validate_tokens(estimated_tokens)

        with self._lock:
            projected_global_calls = self._global["calls"] + 1
            projected_global_tokens = self._global["tokens"] + tokens
            projected_arm_calls = self._arms[arm_name]["calls"] + 1
            projected_arm_tokens = self._arms[arm_name]["tokens"] + tokens

            if projected_global_calls > self.limits.global_calls:
                raise BudgetExceeded("global call budget exceeded")
            if projected_global_tokens > self.limits.global_tokens:
                raise BudgetExceeded("global token budget exceeded")
            if projected_arm_calls > self.limits.per_arm_calls:
                raise BudgetExceeded(f"{arm_name} call budget exceeded")
            if projected_arm_tokens > self.limits.per_arm_tokens:
                raise BudgetExceeded(f"{arm_name} token budget exceeded")

            reservation = Reservation(
                reservation_id=uuid.uuid4().hex,
                arm=arm_name,
                estimated_tokens=tokens,
            )
            self._global["calls"] = projected_global_calls
            self._global["tokens"] = projected_global_tokens
            self._arms[arm_name]["calls"] = projected_arm_calls
            self._arms[arm_name]["tokens"] = projected_arm_tokens
            self._in_flight[reservation.reservation_id] = reservation
            return reservation

    def settle(self, reservation: Reservation, usage: Usage | None) -> None:
        if not isinstance(reservation, Reservation):
            raise TypeError("reservation must be a Reservation")
        if usage is not None and not isinstance(usage, Usage):
            raise TypeError("usage must be a Usage or None")

        with self._lock:
            known = self._in_flight.get(reservation.reservation_id)
            if known is None:
                if reservation.reservation_id in self._settled:
                    raise ValueError("reservation already settled")
                raise ValueError("unknown reservation")
            if known != reservation:
                raise ValueError("reservation does not belong to this authority")

            actual_tokens = (
                reservation.estimated_tokens if usage is None else usage.total_tokens
            )
            delta = actual_tokens - reservation.estimated_tokens
            self._in_flight.pop(reservation.reservation_id, None)
            self._settled.add(reservation.reservation_id)
            projected_global = self._global["tokens"] + delta
            projected_arm = self._arms[reservation.arm]["tokens"] + delta
            if (
                projected_global > self.limits.global_tokens
                or projected_arm > self.limits.per_arm_tokens
            ):
                # The provider has already answered, so the overage is recorded
                # in the ledger by the gateway. Keep authoritative counters at
                # their hard ceilings to fail every later admission closed.
                self._global["tokens"] = min(
                    max(projected_global, 0), self.limits.global_tokens
                )
                self._arms[reservation.arm]["tokens"] = min(
                    max(projected_arm, 0), self.limits.per_arm_tokens
                )
                raise BudgetExceeded("settled token budget exceeded")
            self._global["tokens"] = projected_global
            self._arms[reservation.arm]["tokens"] = projected_arm

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "limits": self.limits.to_dict(),
                "global": dict(self._global),
                "arms": {
                    arm: dict(stats)
                    for arm, stats in sorted(self._arms.items())
                },
                "in_flight": [
                    {
                        "reservation_id": reservation.reservation_id,
                        "arm": reservation.arm,
                        "estimated_tokens": reservation.estimated_tokens,
                    }
                    for reservation in self._in_flight.values()
                ],
                "recovered_pending": [
                    {
                        "reservation_id": reservation.reservation_id,
                        "arm": reservation.arm,
                        "estimated_tokens": reservation.estimated_tokens,
                    }
                    for reservation in self._recovered_pending.values()
                ],
            }

    @staticmethod
    def _validate_arm(arm: str) -> str:
        if arm not in _ALLOWED_ARMS:
            allowed = ", ".join(sorted(_ALLOWED_ARMS))
            raise ValueError(f"arm must be one of: {allowed}")
        return arm

    @staticmethod
    def _validate_tokens(estimated_tokens: int) -> int:
        if isinstance(estimated_tokens, bool) or not isinstance(estimated_tokens, int):
            raise TypeError("estimated_tokens must be an integer")
        if estimated_tokens <= 0:
            raise ValueError("estimated_tokens must be positive")
        return estimated_tokens

    def _restore(self, records: Iterable[Mapping[str, Any]]) -> None:
        """Rehydrate durable call/token usage before accepting new work."""

        reservations: dict[str, Reservation] = {}
        settled: set[str] = set()
        for record in records:
            if not isinstance(record, Mapping):
                raise ConfigurationMismatch("ledger contains a non-object record")
            event = record.get("event")
            if event is None:
                self._restore_legacy_record(record)
                continue
            if event == "attempt_denied":
                self._validate_denied_record(record)
                continue
            if event == "attempt_reserved":
                reservation = self._restore_reservation(record, reservations)
                reservations[reservation.reservation_id] = reservation
                self._apply_usage(
                    reservation.arm,
                    calls=1,
                    tokens=reservation.estimated_tokens,
                )
                continue
            if event == "attempt_settled":
                reservation_id = self._reservation_id(record)
                reservation = reservations.get(reservation_id)
                if reservation is None or reservation_id in settled:
                    raise ConfigurationMismatch(
                        "ledger contains an orphan or duplicate settlement"
                    )
                arm = self._record_arm(record)
                calls = self._record_integer(record, "calls", minimum=0)
                delta = self._record_integer(record, "tokens", minimum=None)
                charged = self._record_integer(
                    record, "charged_tokens", minimum=0
                )
                reserved = self._record_integer(
                    record, "reserved_tokens", minimum=1
                )
                if (
                    arm != reservation.arm
                    or calls != 0
                    or reserved != reservation.estimated_tokens
                    or delta != charged - reserved
                ):
                    raise ConfigurationMismatch(
                        "ledger contains an invalid settlement"
                    )
                self._apply_settlement(
                    arm,
                    delta=delta,
                    exceeded=record.get("status")
                    == "settled_budget_exceeded",
                )
                settled.add(reservation_id)
                continue
            raise ConfigurationMismatch("ledger contains an unknown budget event")

        self._recovered_pending = {
            reservation_id: reservation
            for reservation_id, reservation in reservations.items()
            if reservation_id not in settled
        }

    def _restore_legacy_record(self, record: Mapping[str, Any]) -> None:
        arm = self._record_arm(record)
        calls = self._record_integer(record, "calls", minimum=0)
        tokens = self._record_integer(record, "tokens", minimum=0)
        self._apply_usage(arm, calls=calls, tokens=tokens)

    def _validate_denied_record(self, record: Mapping[str, Any]) -> None:
        self._record_arm(record)
        calls = self._record_integer(record, "calls", minimum=0)
        tokens = self._record_integer(record, "tokens", minimum=0)
        if calls != 0 or tokens != 0:
            raise ConfigurationMismatch("ledger contains an invalid denial event")

    def _restore_reservation(
        self,
        record: Mapping[str, Any],
        reservations: Mapping[str, Reservation],
    ) -> Reservation:
        reservation_id = self._reservation_id(record)
        if reservation_id in reservations:
            raise ConfigurationMismatch("ledger contains a duplicate reservation")
        arm = self._record_arm(record)
        calls = self._record_integer(record, "calls", minimum=0)
        tokens = self._record_integer(record, "tokens", minimum=1)
        reserved = self._record_integer(record, "reserved_tokens", minimum=1)
        if calls != 1 or tokens != reserved:
            raise ConfigurationMismatch("ledger contains an invalid reservation")
        return Reservation(
            reservation_id=reservation_id,
            arm=arm,
            estimated_tokens=reserved,
        )

    @staticmethod
    def _reservation_id(record: Mapping[str, Any]) -> str:
        value = record.get("reservation_id")
        try:
            return validate_identifier(value, "reservation_id")
        except (TypeError, ValueError) as exc:
            raise ConfigurationMismatch(
                "ledger contains an invalid reservation id"
            ) from exc

    @staticmethod
    def _record_arm(record: Mapping[str, Any]) -> str:
        arm = record.get("arm")
        if arm not in _ALLOWED_ARMS:
            raise ConfigurationMismatch(
                "ledger contains usage for an unsupported arm"
            )
        return arm

    @staticmethod
    def _record_integer(
        record: Mapping[str, Any],
        field: str,
        *,
        minimum: int | None,
    ) -> int:
        value = record.get(field)
        if isinstance(value, bool) or not isinstance(value, int):
            raise ConfigurationMismatch("ledger contains invalid usage counters")
        if minimum is not None and value < minimum:
            raise ConfigurationMismatch("ledger contains invalid usage counters")
        return value

    def _apply_usage(self, arm: str, *, calls: int, tokens: int) -> None:
        global_calls = self._global["calls"] + calls
        global_tokens = self._global["tokens"] + tokens
        arm_calls = self._arms[arm]["calls"] + calls
        arm_tokens = self._arms[arm]["tokens"] + tokens
        if min(global_calls, global_tokens, arm_calls, arm_tokens) < 0:
            raise ConfigurationMismatch("ledger usage counters underflow")
        self._global["calls"] = global_calls
        self._global["tokens"] = global_tokens
        self._arms[arm]["calls"] = arm_calls
        self._arms[arm]["tokens"] = arm_tokens

    def _apply_settlement(
        self,
        arm: str,
        *,
        delta: int,
        exceeded: bool,
    ) -> None:
        projected_global = self._global["tokens"] + delta
        projected_arm = self._arms[arm]["tokens"] + delta
        if min(projected_global, projected_arm) < 0:
            raise ConfigurationMismatch("ledger usage counters underflow")
        over_limit = (
            projected_global > self.limits.global_tokens
            or projected_arm > self.limits.per_arm_tokens
        )
        if exceeded:
            if not over_limit or delta <= 0:
                raise ConfigurationMismatch(
                    "ledger budget-exceeded settlement is inconsistent"
                )
            self._global["tokens"] = min(
                projected_global, self.limits.global_tokens
            )
            self._arms[arm]["tokens"] = min(
                projected_arm, self.limits.per_arm_tokens
            )
            return
        if over_limit:
            raise ConfigurationMismatch(
                "ledger settlement exceeds the immutable budget"
            )
        self._global["tokens"] = projected_global
        self._arms[arm]["tokens"] = projected_arm
