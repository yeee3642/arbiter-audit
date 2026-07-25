"""Provider backends for the automation gateway."""

from __future__ import annotations

import json
import re
from typing import Any, Protocol

import httpx

from .contracts import (
    AIS3_BASE_URL,
    AIS3_PINNED_MODEL,
    GatewayRequest,
    ProviderPermanentError,
    ProviderResult,
    ProviderTransientError,
    Usage,
    estimate_tokens,
    sha256_json,
)

_HEADER_RE = re.compile(
    r"FILE\s+(?P<path>.+?)\s+\|\s+CONTRACT\s+(?P<contract>.+?)\s+\|\s+FUNCTION\s+"
    r"(?P<function>.+?)\s+\|\s+L(?P<start>\d+)-L(?P<end>\d+)"
)
_SEVERITIES = ("High", "Medium", "Low")


class ProviderBackend(Protocol):
    def complete(self, request: GatewayRequest) -> ProviderResult:
        ...

    def close(self) -> None:
        ...


def _extract_header_fields(request: GatewayRequest) -> dict[str, str]:
    for message in request.messages:
        content = message.get("content")
        if not isinstance(content, str):
            continue
        match = _HEADER_RE.search(content)
        if match:
            return {
                "path": match.group("path").strip(),
                "contract": match.group("contract").strip(),
                "function": match.group("function").strip(),
                "evidence": f"L{match.group('start')}-L{match.group('end')}",
            }
    seed = sha256_json(
        {
            "subject_id": request.subject_id,
            "stage": request.stage,
            "surface": request.surface,
            "arm": request.arm,
            "messages": list(request.messages),
        }
    )
    return {
        "path": f"{request.subject_id}.sol",
        "contract": f"Contract{seed[:8]}",
        "function": f"mockFunction_{seed[8:16]}",
        "evidence": f"L{int(seed[16:20], 16) % 180 + 1}-L{int(seed[20:24], 16) % 180 + 2}",
    }


def _content_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text" and isinstance(
                item.get("text"), str
            ):
                parts.append(item["text"])
        if parts:
            return "".join(parts)
    raise ProviderPermanentError("provider payload missing text content")


class MockProvider:
    """Deterministic backend for integration and offline tests."""

    def complete(self, request: GatewayRequest) -> ProviderResult:
        fields = _extract_header_fields(request)
        seed = sha256_json(
            {
                "subject_id": request.subject_id,
                "surface": request.surface,
                "stage": request.stage,
                "messages": list(request.messages),
                "max_tokens": request.max_tokens,
            }
        )
        severity = _SEVERITIES[int(seed[:2], 16) % len(_SEVERITIES)]
        confidence = round((int(seed[2:6], 16) % 1000) / 1000, 3)

        if request.surface == "n8n":
            payload: list[dict[str, Any]] = [
                {
                    "summary": (
                        f"Deterministic mock audit for {request.subject_id} "
                        f"via {fields['contract']}.{fields['function']}"
                    ),
                    "severity": severity.lower(),
                    "vulnerability_details": {
                        "function_name": fields["function"],
                        "description": (
                            f"Stable mock report for {fields['contract']}.{fields['function']} "
                            f"on subject {request.subject_id}."
                        ),
                    },
                    "code_snippet": [
                        f"// FILE {fields['path']} | CONTRACT {fields['contract']} | "
                        f"FUNCTION {fields['function']} | {fields['evidence']}"
                    ],
                    "recommendation": (
                        f"Review {fields['contract']}.{fields['function']} in {fields['path']}."
                    ),
                }
            ]
        else:
            payload = {
                "findings": [
                    {
                        "contract": fields["contract"],
                        "function": fields["function"],
                        "vulnerable": True,
                        "subtag": f"mock-{seed[6:14]}",
                        "severity": severity,
                        "description": (
                            f"Deterministic mock finding for {request.subject_id} "
                            f"at {fields['contract']}.{fields['function']}."
                        ),
                        "evidence": fields["evidence"],
                        "confidence": confidence,
                    }
                ]
            }

        text = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        usage = Usage(
            input_tokens=request.estimated_input_tokens,
            output_tokens=estimate_tokens(text),
        )
        return ProviderResult(text=text, usage=usage, finish_reason="stop")

    def close(self) -> None:
        return


class AIS3Provider:
    """Pinned sync HTTP provider for the AIS3 OpenAI-compatible endpoint."""

    def __init__(
        self,
        api_key: str,
        *,
        endpoint: str = AIS3_BASE_URL,
        model: str = AIS3_PINNED_MODEL,
        timeout_s: float = 120.0,
        client: httpx.Client | None = None,
    ) -> None:
        if not api_key:
            raise ValueError("api_key is required")
        if endpoint.rstrip("/") != AIS3_BASE_URL:
            raise ValueError(f"endpoint must be pinned to {AIS3_BASE_URL}")
        if model != AIS3_PINNED_MODEL:
            raise ValueError(f"model must be pinned to {AIS3_PINNED_MODEL}")
        self._url = f"{AIS3_BASE_URL}/chat/completions"
        self._model = AIS3_PINNED_MODEL
        self._owns_client = client is None
        self._client = client or httpx.Client(
            timeout=httpx.Timeout(timeout_s),
            headers={"Authorization": f"Bearer {api_key}"},
        )

    def complete(self, request: GatewayRequest) -> ProviderResult:
        payload = {
            "model": self._model,
            "messages": list(request.messages),
            "temperature": request.temperature,
            "max_tokens": request.max_tokens,
            "n": 1,
        }
        try:
            response = self._client.post(self._url, json=payload)
        except httpx.TimeoutException as exc:
            raise ProviderTransientError("provider request timed out") from exc
        except httpx.RequestError as exc:
            raise ProviderTransientError("provider network error") from exc

        status = response.status_code
        if status in {408, 425, 429} or status >= 500:
            raise ProviderTransientError(f"provider temporarily unavailable (HTTP {status})")
        if status != 200:
            raise ProviderPermanentError(f"provider rejected request (HTTP {status})")

        try:
            body = response.json()
        except ValueError as exc:
            raise ProviderPermanentError("provider returned malformed JSON") from exc
        if not isinstance(body, dict):
            raise ProviderPermanentError("provider payload was not a JSON object")

        choices = body.get("choices")
        if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
            raise ProviderPermanentError("provider payload missing choices")
        choice = choices[0]
        message = choice.get("message")
        if not isinstance(message, dict):
            raise ProviderPermanentError("provider payload missing message")
        text = _content_text(message.get("content"))

        usage_payload = body.get("usage")
        if not isinstance(usage_payload, dict):
            raise ProviderPermanentError("provider payload missing usage")
        try:
            usage = Usage(
                input_tokens=int(usage_payload.get("prompt_tokens")),
                output_tokens=int(usage_payload.get("completion_tokens")),
            )
        except (TypeError, ValueError) as exc:
            raise ProviderPermanentError("provider usage payload was invalid") from exc

        finish_reason = choice.get("finish_reason")
        if finish_reason is None:
            finish_reason = "stop"
        elif not isinstance(finish_reason, str):
            raise ProviderPermanentError("provider finish reason was invalid")

        return ProviderResult(text=text, usage=usage, finish_reason=finish_reason)

    def close(self) -> None:
        if self._owns_client:
            self._client.close()
