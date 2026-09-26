"""Pinned automation gateway with budgeted retries and redacted ledgering."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any, Protocol

from .contracts import (
    AIS3_PINNED_MODEL,
    BudgetExceeded,
    ConfigurationMismatch,
    GatewayProfile,
    GatewayRequest,
    GatewayResult,
    ModelMismatch,
    ProviderPermanentError,
    ProviderTransientError,
    Usage,
    sha256_text,
)
from .provider import ProviderBackend

_SURFACE_ARM = {
    "openai": "bastet-cc",
    "n8n": "upstream",
}
_RETRY_DELAYS = (2.0, 8.0, 32.0)


class _BudgetAuthority(Protocol):
    def reserve(self, arm: str, estimated_tokens: int) -> Any:
        ...

    def settle(self, reservation: Any, usage: Usage | None) -> Any:
        ...

    def snapshot(self) -> Any:
        ...


class _Ledger(Protocol):
    def append(self, record: dict[str, Any]) -> Any:
        ...

    def summary(self) -> Any:
        ...


class Gateway:
    def __init__(
        self,
        profile: GatewayProfile,
        budget: _BudgetAuthority,
        ledger: _Ledger,
        provider: ProviderBackend,
        max_attempts: int = 3,
        sleep_fn: Callable[[float], None] = time.sleep,
    ) -> None:
        if not isinstance(max_attempts, int) or isinstance(max_attempts, bool) or max_attempts <= 0:
            raise ValueError("max_attempts must be a positive integer")
        self.profile = profile
        self.budget = budget
        self.ledger = ledger
        self.provider = provider
        self.max_attempts = max_attempts
        self.sleep_fn = sleep_fn

    def complete(self, req: GatewayRequest) -> GatewayResult:
        self._validate_request(req)
        # Reserve worst-case output headroom before the provider call, then
        # reconcile down to actual usage. This keeps the hard token ceiling
        # enforceable even though no endpoint tokenizer is available locally.
        estimated_tokens = req.estimated_input_tokens + req.max_tokens
        attempts_made = 0
        last_transient: ProviderTransientError | None = None

        for attempt in range(1, self.max_attempts + 1):
            reservation: Any | None = None
            try:
                reservation = self.budget.reserve(req.arm, estimated_tokens)
            except BudgetExceeded as exc:
                self._append_denied(
                    req=req,
                    attempt=attempt,
                    error_class=type(exc).__name__,
                )
                raise
            self._append_reserved(
                req=req,
                attempt=attempt,
                reservation=reservation,
            )

            attempts_made = attempt
            usage: Usage | None = None
            status = "error"
            error_class: str | None = None
            result = None
            provider_exc: Exception | None = None
            try:
                result = self.provider.complete(req)
                usage = result.usage
                status = "ok"
            except ProviderTransientError as exc:
                provider_exc = exc
                status = "transient_error"
                error_class = type(exc).__name__
                last_transient = exc
            except ProviderPermanentError as exc:
                provider_exc = exc
                status = "permanent_error"
                error_class = type(exc).__name__
            finally:
                self._finalize_attempt(
                    reservation=reservation,
                    usage=usage,
                    req=req,
                    attempt=attempt,
                    status=status,
                    error_class=error_class,
                )

            if result is not None:
                return GatewayResult(
                    request_id=req.request_id,
                    text=result.text,
                    usage=result.usage,
                    provider_attempts=attempts_made,
                    finish_reason=result.finish_reason,
                )

            if isinstance(provider_exc, ProviderPermanentError):
                raise provider_exc
            if isinstance(provider_exc, ProviderTransientError):
                if attempt >= self.max_attempts:
                    break
                self.sleep_fn(_RETRY_DELAYS[min(attempt - 1, len(_RETRY_DELAYS) - 1)])
                continue
            raise ProviderPermanentError("provider attempt failed unexpectedly")

        error_name = type(last_transient).__name__ if last_transient is not None else "ProviderTransientError"
        raise ProviderPermanentError(
            f"provider request failed after {attempts_made} transient attempt(s): {error_name}"
        )

    def close(self) -> None:
        self.provider.close()

    def _validate_request(self, req: GatewayRequest) -> None:
        if req.experiment_id != self.profile.experiment_id:
            raise ConfigurationMismatch("request experiment_id does not match the gateway profile")
        if req.subject_id != self.profile.subject_id:
            raise ConfigurationMismatch("request subject_id does not match the gateway profile")
        if self.profile.model != AIS3_PINNED_MODEL or req.requested_model != self.profile.model:
            raise ModelMismatch(f"model must be pinned to {AIS3_PINNED_MODEL}")
        expected_arm = _SURFACE_ARM.get(req.surface)
        if expected_arm is None:
            raise ConfigurationMismatch(f"unsupported surface {req.surface!r}")
        if req.arm != expected_arm:
            raise ConfigurationMismatch(
                f"surface {req.surface!r} must use arm {expected_arm!r}"
            )

    def _finalize_attempt(
        self,
        *,
        reservation: Any,
        usage: Usage | None,
        req: GatewayRequest,
        attempt: int,
        status: str,
        error_class: str | None,
    ) -> None:
        settle_error: Exception | None = None
        charged_usage = usage or Usage(
            input_tokens=req.estimated_input_tokens, output_tokens=0
        )
        try:
            self.budget.settle(reservation, charged_usage)
        except BudgetExceeded as exc:
            settle_error = exc
            status = "settled_budget_exceeded"
            error_class = type(exc).__name__
        except Exception:
            # The durable reservation remains charged at its worst-case value.
            # Do not append a refund when the in-memory authority could not
            # prove settlement.
            raise
        self._append_settled(
            req=req,
            attempt=attempt,
            reservation=reservation,
            status=status,
            usage=usage,
            charged_tokens=charged_usage.total_tokens,
            error_class=error_class,
        )
        if settle_error is not None:
            raise settle_error

    def _record_base(
        self,
        *,
        req: GatewayRequest,
        attempt: int,
    ) -> dict[str, Any]:
        return {
            "experiment_id": req.experiment_id,
            "subject_id": req.subject_id,
            "surface": req.surface,
            "arm": req.arm,
            "stage": req.stage,
            "request_id": req.request_id,
            "context_namespace_sha256": sha256_text(req.context_namespace),
            "model": self.profile.model,
            "attempt": attempt,
            "estimated_input_tokens": req.estimated_input_tokens,
        }

    def _append_reserved(
        self,
        *,
        req: GatewayRequest,
        attempt: int,
        reservation: Any,
    ) -> None:
        self.ledger.append(
            {
                **self._record_base(req=req, attempt=attempt),
                "event": "attempt_reserved",
                "reservation_id": reservation.reservation_id,
                "status": "reserved",
                "calls": 1,
                "tokens": reservation.estimated_tokens,
                "reserved_tokens": reservation.estimated_tokens,
                "usage": None,
                "error_class": None,
            }
        )

    def _append_settled(
        self,
        *,
        req: GatewayRequest,
        attempt: int,
        reservation: Any,
        status: str,
        usage: Usage | None,
        charged_tokens: int,
        error_class: str | None,
    ) -> None:
        self.ledger.append(
            {
                **self._record_base(req=req, attempt=attempt),
                "event": "attempt_settled",
                "reservation_id": reservation.reservation_id,
                "status": status,
                "calls": 0,
                "tokens": charged_tokens - reservation.estimated_tokens,
                "reserved_tokens": reservation.estimated_tokens,
                "charged_tokens": charged_tokens,
                "usage": usage.to_dict() if usage is not None else None,
                "error_class": error_class,
            }
        )

    def _append_denied(
        self,
        *,
        req: GatewayRequest,
        attempt: int,
        error_class: str,
    ) -> None:
        self.ledger.append(
            {
                **self._record_base(req=req, attempt=attempt),
                "event": "attempt_denied",
                "status": "budget_denied",
                "calls": 0,
                "tokens": 0,
                "usage": None,
                "error_class": error_class,
            }
        )
