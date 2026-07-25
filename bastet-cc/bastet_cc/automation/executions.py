"""Durable completed-execution store for the upstream n8n compatibility surface."""

from __future__ import annotations

import json
import os
from copy import deepcopy
from pathlib import Path
from threading import RLock
from typing import Any

from ..redact import redact
from .contracts import ConfigurationMismatch, ExecutionRecord, validate_identifier

EXECUTION_STORE_VERSION = "n8n-executions-v1"


class ExecutionStore:
    """Append completed executions before their ids are returned to callers."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = RLock()
        self._records = self._load()

    def put(self, record: ExecutionRecord) -> None:
        if not isinstance(record, ExecutionRecord):
            raise TypeError("record must be an ExecutionRecord")
        validate_identifier(record.execution_id, "execution_id")
        validate_identifier(record.request_id, "request_id")

        payload = {
            "store_version": EXECUTION_STORE_VERSION,
            "execution_id": record.execution_id,
            "workflow_name": record.workflow_name,
            "request_id": record.request_id,
            "output": _sanitize(record.output),
            "finished": record.finished,
            "error": _sanitize(record.error),
        }
        restored = _decode_record(payload, line_number=None)

        with self._lock:
            if restored.execution_id in self._records:
                raise ConfigurationMismatch("execution store contains a duplicate id")
            line = json.dumps(payload, ensure_ascii=False, sort_keys=True)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(line + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            self._records[restored.execution_id] = restored

    def get(self, execution_id: str) -> ExecutionRecord | None:
        validate_identifier(execution_id, "execution_id")
        with self._lock:
            record = self._records.get(execution_id)
            return deepcopy(record) if record is not None else None

    def count(self) -> int:
        with self._lock:
            return len(self._records)

    def _load(self) -> dict[str, ExecutionRecord]:
        if not self.path.exists():
            return {}

        records: dict[str, ExecutionRecord] = {}
        try:
            with self.path.open("r", encoding="utf-8") as handle:
                for line_number, line in enumerate(handle, start=1):
                    if not line.strip():
                        continue
                    try:
                        payload = json.loads(line)
                    except json.JSONDecodeError as exc:
                        raise ConfigurationMismatch(
                            f"execution store line {line_number} is unreadable"
                        ) from exc
                    record = _decode_record(payload, line_number=line_number)
                    if record.execution_id in records:
                        raise ConfigurationMismatch(
                            "execution store contains a duplicate id"
                        )
                    records[record.execution_id] = record
        except OSError as exc:
            raise ConfigurationMismatch("execution store is unreadable") from exc
        return records


def _decode_record(payload: Any, line_number: int | None) -> ExecutionRecord:
    where = f" line {line_number}" if line_number is not None else ""
    if not isinstance(payload, dict):
        raise ConfigurationMismatch(f"execution store{where} must be a JSON object")
    if payload.get("store_version") != EXECUTION_STORE_VERSION:
        raise ConfigurationMismatch(f"execution store{where} has an unknown version")

    execution_id = payload.get("execution_id")
    workflow_name = payload.get("workflow_name")
    request_id = payload.get("request_id")
    output = payload.get("output")
    finished = payload.get("finished")
    error = payload.get("error")
    try:
        validate_identifier(execution_id, "execution_id")
        validate_identifier(request_id, "request_id")
    except (TypeError, ValueError) as exc:
        raise ConfigurationMismatch(
            f"execution store{where} contains an invalid identifier"
        ) from exc
    if not isinstance(workflow_name, str) or not workflow_name:
        raise ConfigurationMismatch(
            f"execution store{where} contains an invalid workflow name"
        )
    if not isinstance(output, list) or any(not isinstance(item, dict) for item in output):
        raise ConfigurationMismatch(
            f"execution store{where} contains an invalid output"
        )
    if not isinstance(finished, bool):
        raise ConfigurationMismatch(
            f"execution store{where} contains an invalid finished flag"
        )
    if error is not None and not isinstance(error, str):
        raise ConfigurationMismatch(
            f"execution store{where} contains an invalid error"
        )

    return ExecutionRecord(
        execution_id=execution_id,
        workflow_name=workflow_name,
        request_id=request_id,
        output=tuple(deepcopy(output)),
        finished=finished,
        error=error,
    )


def _sanitize(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _sanitize(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_sanitize(item) for item in value]
    if isinstance(value, str):
        return redact(value)
    return value
