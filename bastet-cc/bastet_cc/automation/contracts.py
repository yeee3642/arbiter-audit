"""Versioned contracts shared by the automation gateway and both HTTP surfaces."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

AIS3_BASE_URL = "https://llm-api.zoolab.org/v1"
AIS3_PINNED_MODEL = "ais3/llama-3.1-8b"
PROFILE_VERSION = "ais3-fair-ab-v2"
ADAPTER_VERSION = "dual-surface-v2"
SCHEMA_VERSION = "bastet-audit-v1"
SUPPORTED_WORKFLOW = "flashloan"
ALLOWED_STAGES = frozenset({"scan", "detect", "verify", "repair"})

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_SECRET_LIKE_ID = re.compile(
    r"(?i)(?:[0-9a-f]{40,128}|(?:sk|pk|rk|ghp|gho|ghs|ghu|xox[baprs])[-_][A-Za-z0-9_-]{16,})"
)


class AutomationError(RuntimeError):
    """Base class for errors that are safe to render without provider details."""


class ConfigurationMismatch(AutomationError):
    """An existing experiment or request does not match the immutable profile."""


class BudgetExceeded(AutomationError):
    """A request would exceed the configured fair-use budget."""


class ModelMismatch(AutomationError):
    """A caller requested anything other than the pinned AIS3 model."""


class UnsupportedWorkflow(AutomationError):
    """The selected upstream workflow cannot be faithfully lowered in Phase 1."""


class ProviderTransientError(AutomationError):
    """A provider attempt may succeed when retried by the gateway."""


class ProviderPermanentError(AutomationError):
    """A provider request cannot succeed without changing its inputs."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_json(value: Any) -> str:
    return sha256_text(canonical_json(value))


def validate_identifier(value: str, field_name: str) -> str:
    if not _SAFE_ID.fullmatch(value):
        raise ValueError(
            f"{field_name} must be 1-128 characters using letters, digits, '.', '_', ':', or '-'"
        )
    if _SECRET_LIKE_ID.search(value):
        raise ValueError(f"{field_name} must not contain credential-shaped material")
    return value


def estimate_tokens(value: str | list[dict[str, Any]]) -> int:
    """Conservative tokenizer-free estimate used only for preflight admission."""

    text = value if isinstance(value, str) else canonical_json(value)
    return max(1, (len(text) + 3) // 4)


def new_request_id() -> str:
    return uuid.uuid4().hex


@dataclass(frozen=True)
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0

    def __post_init__(self) -> None:
        if self.input_tokens < 0 or self.output_tokens < 0:
            raise ValueError("token usage cannot be negative")

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens

    def to_dict(self) -> dict[str, int]:
        return {
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "total_tokens": self.total_tokens,
        }


@dataclass(frozen=True)
class BudgetLimits:
    global_calls: int = 20
    global_tokens: int = 200_000
    per_arm_calls: int = 10
    per_arm_tokens: int = 100_000

    def __post_init__(self) -> None:
        values = asdict(self)
        if any(not isinstance(v, int) or v <= 0 for v in values.values()):
            raise ValueError("all budget limits must be positive integers")
        if self.per_arm_calls > self.global_calls:
            raise ValueError("per-arm call limit cannot exceed global call limit")
        if self.per_arm_tokens > self.global_tokens:
            raise ValueError("per-arm token limit cannot exceed global token limit")

    def to_dict(self) -> dict[str, int]:
        return asdict(self)


@dataclass(frozen=True)
class WorkflowSpec:
    workflow_id: str
    name: str
    webhook_path: str
    prompt: str
    parser_schema: dict[str, Any]
    source_path: Path
    workflow_sha256: str
    prompt_sha256: str
    declared_models: tuple[str, ...]
    chain_llm_count: int
    public_workflow: dict[str, Any] = field(repr=False)


@dataclass(frozen=True)
class GatewayProfile:
    experiment_id: str
    subject_id: str
    provider_mode: Literal["mock", "live"]
    selected_workflow: str
    workflow_sha256: str
    prompt_sha256: str
    budget: BudgetLimits
    endpoint: str = AIS3_BASE_URL
    model: str = AIS3_PINNED_MODEL
    profile_version: str = PROFILE_VERSION
    adapter_version: str = ADAPTER_VERSION
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        validate_identifier(self.experiment_id, "experiment_id")
        validate_identifier(self.subject_id, "subject_id")
        if self.provider_mode not in ("mock", "live"):
            raise ValueError("provider_mode must be 'mock' or 'live'")
        if self.endpoint.rstrip("/") != AIS3_BASE_URL:
            raise ConfigurationMismatch(f"endpoint must be pinned to {AIS3_BASE_URL}")
        if self.model != AIS3_PINNED_MODEL:
            raise ModelMismatch(f"model must be pinned to {AIS3_PINNED_MODEL}")
        if self.selected_workflow != SUPPORTED_WORKFLOW:
            raise UnsupportedWorkflow(
                f"Phase 1 supports only workflow {SUPPORTED_WORKFLOW!r}"
            )

    def fingerprint_payload(self) -> dict[str, Any]:
        return {
            "experiment_id": self.experiment_id,
            "subject_id": self.subject_id,
            "endpoint": self.endpoint,
            "model": self.model,
            "provider_mode": self.provider_mode,
            "selected_workflow": self.selected_workflow,
            "workflow_sha256": self.workflow_sha256,
            "prompt_sha256": self.prompt_sha256,
            "profile_version": self.profile_version,
            "adapter_version": self.adapter_version,
            "schema_version": self.schema_version,
            "budget": self.budget.to_dict(),
            "claim_level": self.claim_level,
        }

    @property
    def fingerprint(self) -> str:
        return sha256_json(self.fingerprint_payload())

    @property
    def claim_level(self) -> str:
        return (
            "pipeline-readiness-only"
            if self.provider_mode == "mock"
            else "live-provider-evidence"
        )

    def manifest(self) -> dict[str, Any]:
        return {
            **self.fingerprint_payload(),
            "fingerprint": self.fingerprint,
            "created_at": utc_now(),
            "credential_source": "environment:AIS3_API_KEY"
            if self.provider_mode == "live"
            else "none:deterministic-mock",
        }


@dataclass(frozen=True)
class GatewayRequest:
    request_id: str
    experiment_id: str
    subject_id: str
    surface: Literal["openai", "n8n"]
    arm: Literal["bastet-cc", "upstream"]
    stage: str
    messages: tuple[dict[str, Any], ...]
    requested_model: str
    max_tokens: int
    temperature: float = 0.0
    schema_kind: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        validate_identifier(self.request_id, "request_id")
        validate_identifier(self.experiment_id, "experiment_id")
        validate_identifier(self.subject_id, "subject_id")
        validate_identifier(self.stage, "stage")
        validate_identifier(self.schema_kind, "schema_kind")
        if self.stage not in ALLOWED_STAGES:
            allowed = ", ".join(sorted(ALLOWED_STAGES))
            raise ValueError(f"stage must be one of: {allowed}")
        if self.max_tokens <= 0:
            raise ValueError("max_tokens must be positive")

    @property
    def estimated_input_tokens(self) -> int:
        return estimate_tokens(list(self.messages))

    @property
    def context_namespace(self) -> str:
        return ":".join(
            (
                PROFILE_VERSION,
                ADAPTER_VERSION,
                self.experiment_id,
                self.subject_id,
                self.surface,
                self.arm,
                self.stage,
                self.schema_kind,
                self.request_id,
            )
        )


@dataclass(frozen=True)
class ProviderResult:
    text: str
    usage: Usage
    finish_reason: str = "stop"


@dataclass(frozen=True)
class GatewayResult:
    request_id: str
    text: str
    usage: Usage
    provider_attempts: int
    finish_reason: str = "stop"


@dataclass(frozen=True)
class ExecutionRecord:
    execution_id: str
    workflow_name: str
    request_id: str
    output: tuple[dict[str, Any], ...]
    finished: bool = True
    error: str | None = None
