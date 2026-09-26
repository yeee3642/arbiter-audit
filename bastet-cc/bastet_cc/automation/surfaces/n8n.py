"""Minimal n8n-compatible execution surface for upstream Bastet scans."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from copy import deepcopy
from typing import Any

from ..contracts import AIS3_PINNED_MODEL, AutomationError, ExecutionRecord, GatewayRequest, new_request_id
from ..executions import ExecutionStore

_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)


class N8NSurfaceError(AutomationError):
    """Base class for safe n8n-surface failures."""


class UnknownWebhookRoute(N8NSurfaceError):
    """A webhook route did not resolve to the selected workflow."""


class UnknownExecution(N8NSurfaceError):
    """An execution id is not present in the in-memory execution store."""


class ProviderOutputMalformed(N8NSurfaceError):
    """The upstream arm returned a body that cannot be lowered to AuditReport[] ."""


class N8NSurface:
    def __init__(self, registry, gateway, execution_store: ExecutionStore) -> None:
        self.registry = registry
        self.gateway = gateway
        self.execution_store = execution_store

    @property
    def profile(self):
        return self.gateway.profile

    def workflows_payload(self) -> dict[str, Any]:
        return {"data": self.registry.public_workflows()}

    def submit(
        self,
        path: str,
        body: dict[str, Any],
        headers: Mapping[str, str] | None = None,
    ) -> str:
        workflow = self._workflow_for_path(path)
        prompt = self._validated_prompt(body)
        request = self._build_request(workflow, prompt, headers)
        result = self.gateway.complete(request)
        output = self._parse_provider_output(result.text)
        execution_id = new_request_id()
        record = ExecutionRecord(
            execution_id=execution_id,
            workflow_name=workflow.name,
            request_id=result.request_id,
            output=output,
            finished=True,
        )
        self.execution_store.put(record)
        return execution_id

    def execution_payload(self, execution_id: str) -> dict[str, Any]:
        record = self.execution_store.get(execution_id)
        if record is None:
            raise UnknownExecution("execution id was not found")

        output = [deepcopy(item) for item in record.output]
        last = record.workflow_name
        return {
            "finished": record.finished,
            "data": {
                "executionData": {"nodeExecutionStack": []},
                "resultData": {
                    "lastNodeExecuted": last,
                    "runData": {
                        last: [
                            {
                                "data": {
                                    "main": [[{"json": {"output": output}}]],
                                }
                            }
                        ]
                    },
                },
            },
        }

    def _workflow_for_path(self, path: str):
        normalized = _normalize_route(path)
        if not normalized:
            raise UnknownWebhookRoute("workflow webhook route was not found")
        try:
            return self.registry.selected_route(normalized)
        except KeyError as exc:
            raise UnknownWebhookRoute("workflow webhook route was not found") from exc

    def _validated_prompt(self, body: dict[str, Any]) -> str:
        if not isinstance(body, dict):
            raise ValueError("request body must be a JSON object")
        prompt = body.get("prompt")
        if not isinstance(prompt, str) or not prompt.strip():
            raise ValueError("prompt must be a non-empty string")
        return prompt

    def _build_request(self, workflow, prompt: str, headers: Mapping[str, str] | None):
        lowered = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
        experiment_id = lowered.get("x-bastet-experiment", self.profile.experiment_id)
        subject_id = lowered.get("x-bastet-subject", self.profile.subject_id)
        request_id = new_request_id()
        return GatewayRequest(
            request_id=request_id,
            experiment_id=experiment_id,
            subject_id=subject_id,
            surface="n8n",
            arm="upstream",
            stage="scan",
            messages=(
                {"role": "system", "content": workflow.prompt},
                {"role": "user", "content": prompt},
            ),
            requested_model=AIS3_PINNED_MODEL,
            max_tokens=3072,
            temperature=0.0,
        )

    def _parse_provider_output(self, text: str) -> tuple[dict[str, Any], ...]:
        value = _extract_json(text)
        if isinstance(value, dict):
            value = value.get("output")
        if not isinstance(value, list):
            raise ProviderOutputMalformed(
                "provider output did not contain a valid audit-report array"
            )

        sanitized: list[dict[str, Any]] = []
        for item in value:
            if not isinstance(item, dict):
                raise ProviderOutputMalformed(
                    "provider output did not contain a valid audit-report array"
                )
            sanitized.append(_sanitize_report(item))
        return tuple(sanitized)


def _extract_json(text: str) -> Any:
    raw = text.strip()
    for candidate in (raw, *_FENCE_RE.findall(raw)):
        candidate = candidate.strip()
        if not candidate:
            continue
        try:
            return json.loads(candidate)
        except (TypeError, ValueError):
            continue
    decoder = json.JSONDecoder()
    for match in re.finditer(r"[\[{]", raw):
        try:
            value, _ = decoder.raw_decode(raw[match.start() :])
            return value
        except (TypeError, ValueError):
            continue
    raise ProviderOutputMalformed("provider output did not contain valid JSON")


def _sanitize_report(report: dict[str, Any]) -> dict[str, Any]:
    summary = _required_text(report.get("summary"), "summary")
    recommendation = _required_text(report.get("recommendation"), "recommendation")
    severity = _sanitize_severity(report.get("severity"))

    details = report.get("vulnerability_details")
    if not isinstance(details, dict):
        raise ProviderOutputMalformed("provider output contained an invalid report")
    function_name = _required_text(
        _first_value(details, "function_name", "Function Name", "function"),
        "vulnerability_details.function_name",
    )
    description = _required_text(
        _first_value(details, "description", "Description"),
        "vulnerability_details.description",
    )

    code_snippet = _sanitize_code_snippet(report.get("code_snippet", []))
    return {
        "summary": summary,
        "severity": severity,
        "vulnerability_details": {
            "function_name": function_name,
            "description": description,
        },
        "code_snippet": code_snippet,
        "recommendation": recommendation,
    }


def _sanitize_code_snippet(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        text = value.strip()
        return [text] if text else []
    if not isinstance(value, list):
        raise ProviderOutputMalformed("provider output contained an invalid code_snippet")
    sanitized: list[str] = []
    for item in value:
        if isinstance(item, str):
            text = item.strip()
        elif isinstance(item, (int, float)) and not isinstance(item, bool):
            text = str(item)
        else:
            raise ProviderOutputMalformed("provider output contained an invalid code_snippet")
        if text:
            sanitized.append(text)
    return sanitized


def _sanitize_severity(value: Any) -> str:
    if isinstance(value, str):
        severity = value.strip().lower()
    else:
        severity = ""
    return severity if severity in {"high", "medium", "low"} else "high"


def _required_text(value: Any, field_name: str) -> str:
    if isinstance(value, str):
        text = value.strip()
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        text = str(value)
    else:
        raise ProviderOutputMalformed("provider output contained an invalid report")
    if not text:
        raise ProviderOutputMalformed("provider output contained an invalid report")
    return text


def _first_value(mapping: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in mapping:
            return mapping[key]
    return None


def _normalize_route(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    return value.strip().lstrip("/").lstrip("=")
