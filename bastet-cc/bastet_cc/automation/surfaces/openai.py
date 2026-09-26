"""Minimal OpenAI-compatible surface used by Bastet-CC in automation mode."""

from __future__ import annotations

import time
from collections.abc import Mapping
from typing import Any

from ..contracts import (
    ALLOWED_STAGES,
    AIS3_PINNED_MODEL,
    GatewayRequest,
    ModelMismatch,
    new_request_id,
)


class OpenAISurface:
    def __init__(self, gateway) -> None:
        self.gateway = gateway

    @property
    def profile(self):
        return self.gateway.profile

    def models_payload(self) -> dict[str, Any]:
        return {
            "object": "list",
            "data": [
                {
                    "id": AIS3_PINNED_MODEL,
                    "object": "model",
                    "created": 0,
                    "owned_by": "ais3",
                }
            ],
        }

    def complete(
        self,
        payload: dict[str, Any],
        headers: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise ValueError("request body must be a JSON object")

        requested_model = payload.get("model")
        if requested_model != AIS3_PINNED_MODEL:
            raise ModelMismatch(f"model must be pinned to {AIS3_PINNED_MODEL}")

        messages = payload.get("messages")
        if not isinstance(messages, list) or not messages:
            raise ValueError("messages must be a non-empty array")

        clean_messages: list[dict[str, str]] = []
        for item in messages:
            if not isinstance(item, dict):
                raise ValueError("each message must be an object")
            role, content = item.get("role"), item.get("content")
            if role not in {"system", "user", "assistant"} or not isinstance(content, str):
                raise ValueError("message role/content is invalid")
            clean_messages.append({"role": role, "content": content})

        max_tokens = payload.get("max_tokens", 3072)
        temperature = payload.get("temperature", 0.0)
        if not isinstance(max_tokens, int) or isinstance(max_tokens, bool) or max_tokens <= 0:
            raise ValueError("max_tokens must be a positive integer")
        if not isinstance(temperature, (int, float)) or isinstance(temperature, bool):
            raise ValueError("temperature must be numeric")
        if int(payload.get("n", 1)) != 1:
            raise ValueError("only n=1 is supported")

        lowered = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
        experiment_id = lowered.get("x-bastet-experiment", self.profile.experiment_id)
        subject_id = lowered.get("x-bastet-subject", self.profile.subject_id)
        stage = lowered.get("x-bastet-stage", "detect")
        if stage not in ALLOWED_STAGES - {"scan"}:
            allowed = ", ".join(sorted(ALLOWED_STAGES - {"scan"}))
            raise ValueError(f"OpenAI stage must be one of: {allowed}")
        # Request ids are always generated inside the trust boundary. Accepting
        # an arbitrary header here would let a local caller persist a pasted key
        # or other high-entropy value in the append-only ledger.
        request_id = new_request_id()

        request = GatewayRequest(
            request_id=request_id,
            experiment_id=experiment_id,
            subject_id=subject_id,
            surface="openai",
            arm="bastet-cc",
            stage=stage,
            messages=tuple(clean_messages),
            requested_model=requested_model,
            max_tokens=max_tokens,
            temperature=float(temperature),
        )
        result = self.gateway.complete(request)
        return {
            "id": f"chatcmpl-{result.request_id}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": AIS3_PINNED_MODEL,
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": result.text},
                    "finish_reason": result.finish_reason,
                }
            ],
            "usage": {
                "prompt_tokens": result.usage.input_tokens,
                "completion_tokens": result.usage.output_tokens,
                "total_tokens": result.usage.total_tokens,
            },
        }
