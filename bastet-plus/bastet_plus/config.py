"""Configuration for the Bastet+ harness.

Everything is overridable by environment variable so the same code runs against
a local vLLM/Ollama box, the AIS3 gateway, or OpenAI without edits. The original
harness hard-coded ``gpt-4o-mini`` inside 56 separate n8n JSON nodes.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, replace


def _env(name: str, default: str) -> str:
    v = os.getenv(name)
    return v if v not in (None, "") else default


def _env_f(name: str, default: float) -> float:
    try:
        return float(_env(name, str(default)))
    except ValueError:
        return default


def _env_i(name: str, default: int) -> int:
    try:
        return int(_env(name, str(default)))
    except ValueError:
        return default


@dataclass(frozen=True)
class LLMConfig:
    base_url: str = field(default_factory=lambda: _env("BASTET_LLM_BASE_URL", "http://localhost:8000/v1"))
    api_key: str = field(default_factory=lambda: _env("BASTET_LLM_API_KEY", "sk-noauth"))

    # Detection model: does the wide, cheap sweep.
    model: str = field(default_factory=lambda: _env("BASTET_LLM_MODEL", "gpt-4o-mini"))
    # Verification model: judges each candidate. Defaults to the detect model.
    verifier_model: str = field(default_factory=lambda: _env("BASTET_LLM_VERIFIER_MODEL", ""))

    temperature: float = field(default_factory=lambda: _env_f("BASTET_LLM_TEMPERATURE", 0.0))
    top_p: float = field(default_factory=lambda: _env_f("BASTET_LLM_TOP_P", 1.0))
    max_tokens: int = field(default_factory=lambda: _env_i("BASTET_LLM_MAX_TOKENS", 3000))
    seed: int | None = field(default_factory=lambda: _env_i("BASTET_LLM_SEED", 20260725))

    request_timeout: float = field(default_factory=lambda: _env_f("BASTET_LLM_TIMEOUT", 180.0))
    max_retries: int = field(default_factory=lambda: _env_i("BASTET_LLM_MAX_RETRIES", 4))
    concurrency: int = field(default_factory=lambda: _env_i("BASTET_CONCURRENCY", 8))

    # $ per 1M tokens; only used for the cost column in reports.
    price_in: float = field(default_factory=lambda: _env_f("BASTET_PRICE_IN", 0.0))
    price_out: float = field(default_factory=lambda: _env_f("BASTET_PRICE_OUT", 0.0))

    cache_path: str = field(default_factory=lambda: _env("BASTET_CACHE", ".bastet_cache.sqlite3"))
    cache_enabled: bool = field(default_factory=lambda: _env("BASTET_CACHE_ENABLED", "1") != "0")

    def for_verifier(self) -> "LLMConfig":
        return replace(self, model=self.verifier_model or self.model)


@dataclass(frozen=True)
class PipelineConfig:
    """Knobs for the enhanced pipeline.

    ``samples`` > 1 turns on self-consistency: the detector is run k times at
    ``vote_temperature`` and a candidate must be produced by >= ``vote_threshold``
    of the runs to survive. ``verify`` turns on the adversarial second stage.
    """

    # -- input handling ---------------------------------------------------
    slice_code: bool = True
    max_slice_chars: int = 12_000
    context_header_chars: int = 2_500

    # -- self-consistency -------------------------------------------------
    samples: int = 1
    vote_temperature: float = 0.6
    vote_threshold: float = 0.5

    # -- verification -----------------------------------------------------
    verify: bool = True
    verify_votes: int = 1
    require_grounded_snippet: bool = True
    # Findings whose snippet cannot be located in the source are dropped
    # outright when this is on -- a zero-token hallucination filter.
    drop_ungrounded: bool = True

    min_severity: str = "low"


SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}
