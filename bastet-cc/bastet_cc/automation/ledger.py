"""Append-only redacted execution ledger for the automation gateway."""

from __future__ import annotations

import json
import os
from collections import Counter
from pathlib import Path
from threading import RLock
from typing import Any

from ..redact import redact
from .contracts import ConfigurationMismatch, GatewayProfile, sha256_json

_SENSITIVE_KEYS = frozenset(
    {"authorization", "api_key", "password", "access_token", "refresh_token"}
)
_SENSITIVE_MARKER = "[REDACTED]"
_OMITTED_BODY_MARKER = "[OMITTED]"
_BODY_KEYS = frozenset({"prompt", "prompts", "message", "messages"})


class Ledger:
    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = RLock()

    def append(self, record: dict) -> None:
        if not isinstance(record, dict):
            raise TypeError("record must be a dictionary")

        sanitized = self._sanitize(record)
        line = json.dumps(sanitized, ensure_ascii=False, sort_keys=True)

        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(line + "\n")
                handle.flush()
                os.fsync(handle.fileno())

    def records(self) -> list[dict[str, Any]]:
        with self._lock:
            if not self.path.exists():
                return []

            out: list[dict[str, Any]] = []
            with self.path.open("r", encoding="utf-8") as handle:
                for line_number, line in enumerate(handle, start=1):
                    if not line.strip():
                        continue
                    try:
                        item = json.loads(line)
                    except json.JSONDecodeError as exc:
                        raise ConfigurationMismatch(
                            f"ledger line {line_number} is unreadable"
                        ) from exc
                    if not isinstance(item, dict):
                        raise ConfigurationMismatch(
                            f"ledger line {line_number} must be a JSON object"
                        )
                    out.append(item)
            return out

    def summary(self) -> dict[str, Any]:
        by_arm: Counter[str] = Counter()
        by_status: Counter[str] = Counter()
        calls = 0
        tokens = 0
        records = self.records()
        reservations: set[str] = set()
        settled: set[str] = set()

        for record in records:
            arm = record.get("arm")
            status = record.get("status")
            event = record.get("event")
            if isinstance(status, str) and event != "attempt_reserved":
                by_status[status] += 1

            record_calls = record.get("calls")
            if isinstance(record_calls, int) and not isinstance(record_calls, bool):
                calls += record_calls
                if isinstance(arm, str) and record_calls > 0:
                    by_arm[arm] += record_calls

            token_total = self._record_token_total(record)
            if token_total is not None:
                tokens += token_total

            reservation_id = record.get("reservation_id")
            if isinstance(reservation_id, str):
                if event == "attempt_reserved":
                    reservations.add(reservation_id)
                elif event == "attempt_settled":
                    settled.add(reservation_id)

        return {
            "records": len(records),
            "by_arm": dict(sorted(by_arm.items())),
            "by_status": dict(sorted(by_status.items())),
            "calls": calls,
            "tokens": tokens,
            "pending_reservations": len(reservations - settled),
        }

    def _sanitize(self, value: Any) -> Any:
        if isinstance(value, dict):
            sanitized: dict[str, Any] = {}
            for key, item in value.items():
                key_text = str(key)
                key_name = key_text.casefold()
                if key_name in _SENSITIVE_KEYS:
                    sanitized[key_text] = _SENSITIVE_MARKER
                elif key_name in _BODY_KEYS:
                    sanitized[key_text] = _OMITTED_BODY_MARKER
                else:
                    sanitized[key_text] = self._sanitize(item)
            return sanitized
        if isinstance(value, list):
            return [self._sanitize(item) for item in value]
        if isinstance(value, tuple):
            return [self._sanitize(item) for item in value]
        if isinstance(value, Path):
            return str(value)
        if isinstance(value, str):
            return redact(value)
        return value

    @staticmethod
    def _record_token_total(record: dict[str, Any]) -> int | None:
        tokens = record.get("tokens")
        if isinstance(tokens, int) and not isinstance(tokens, bool):
            return tokens

        usage = record.get("usage")
        if not isinstance(usage, dict):
            return None

        total = usage.get("total_tokens")
        if isinstance(total, int) and not isinstance(total, bool):
            return total

        input_tokens = usage.get("input_tokens")
        output_tokens = usage.get("output_tokens")
        if (
            isinstance(input_tokens, int)
            and not isinstance(input_tokens, bool)
            and isinstance(output_tokens, int)
            and not isinstance(output_tokens, bool)
        ):
            return input_tokens + output_tokens
        return None


def ensure_manifest(path: Path, profile: GatewayProfile) -> dict[str, Any]:
    manifest_path = Path(path)
    manifest = Ledger(manifest_path)._sanitize(profile.manifest())

    if manifest_path.exists():
        try:
            existing = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            raise ConfigurationMismatch("existing manifest is unreadable") from exc
        if not isinstance(existing, dict):
            raise ConfigurationMismatch("existing manifest must be a JSON object")
        expected_payload = profile.fingerprint_payload()
        existing_payload = {
            key: existing.get(key) for key in expected_payload
        }
        existing_fingerprint = existing.get("fingerprint")
        if (
            not isinstance(existing_fingerprint, str)
            or sha256_json(existing_payload) != existing_fingerprint
        ):
            raise ConfigurationMismatch(
                "existing manifest fingerprint differs (invalid payload binding)")
        if (
            existing_payload != expected_payload
            or existing_fingerprint != profile.fingerprint
        ):
            raise ConfigurationMismatch("existing manifest fingerprint differs")
        return existing

    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest
