"""Frozen upstream n8n workflow registry for the automation bridge."""

from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from typing import Any

from .contracts import AutomationError, WorkflowSpec, sha256_text


class WorkflowRegistryError(AutomationError):
    """Base class for safe workflow-registry failures."""


class SelectedWorkflowNotFound(WorkflowRegistryError):
    """The requested selected workflow does not exist in the frozen registry."""


class DuplicateSelectedWorkflow(WorkflowRegistryError):
    """Multiple upstream workflow files declared the selected workflow name."""


class EmptyWebhookRoute(WorkflowRegistryError):
    """A workflow declared an empty webhook route after normalization."""


class DuplicateWebhookRoute(WorkflowRegistryError):
    """Multiple workflows declared the same webhook route."""


class UnsupportedSelectedWorkflow(WorkflowRegistryError):
    """The selected workflow shape cannot be faithfully lowered in Phase 1."""


class WorkflowRegistry:
    """Loads upstream workflow JSON files without mutating them."""

    def __init__(
        self,
        workflows: tuple[WorkflowSpec, ...],
        selected: WorkflowSpec,
        route_collisions: dict[str, tuple[str, ...]],
    ) -> None:
        self.workflows = workflows
        self.selected = selected
        self.route_collisions = route_collisions
        self._by_name = {workflow.name: workflow for workflow in workflows}

    @classmethod
    def load(cls, root: Path, selected: str = "flashloan") -> "WorkflowRegistry":
        if not isinstance(root, Path):
            root = Path(root)
        files = sorted(path for path in root.glob("*.json") if path.is_file())

        workflows: list[WorkflowSpec] = []
        selected_matches: list[WorkflowSpec] = []
        routes: dict[str, list[str]] = {}

        for path in files:
            raw = path.read_text(encoding="utf-8")
            data = json.loads(raw)
            spec = _workflow_spec(path, raw, data)

            if not spec.webhook_path:
                raise EmptyWebhookRoute(
                    f"workflow {spec.name!r} has an empty webhook route"
                )
            routes.setdefault(spec.webhook_path, []).append(spec.name)
            workflows.append(spec)
            if spec.name == selected:
                selected_matches.append(spec)

        if not selected_matches:
            raise SelectedWorkflowNotFound(
                f"selected workflow {selected!r} was not found under {str(root)!r}"
            )
        if len(selected_matches) > 1:
            raise DuplicateSelectedWorkflow(
                f"selected workflow {selected!r} is declared by multiple upstream JSON files"
            )

        chosen_name = selected_matches[0].name
        normalized = tuple(
            replace(
                workflow,
                public_workflow=_public_workflow(workflow, active=workflow.name == chosen_name),
            )
            for workflow in workflows
        )
        chosen = next(workflow for workflow in normalized if workflow.name == chosen_name)
        if chosen.chain_llm_count != 1:
            raise UnsupportedSelectedWorkflow(
                f"selected workflow {chosen.name!r} must contain exactly one chainLlm node"
            )
        # Route collisions in the frozen upstream are evidence, not an active
        # ambiguity here: this Phase 1 registry exposes exactly one explicitly
        # selected workflow. If selection ever becomes multi-workflow, these
        # collisions must become a hard error again.
        route_collisions = {
            route: tuple(names)
            for route, names in sorted(routes.items())
            if len(names) > 1
        }
        return cls(normalized, chosen, route_collisions)

    def public_workflows(self) -> list[dict[str, Any]]:
        return [deepcopy(self.selected.public_workflow)]

    def selected_route(self, route: str) -> WorkflowSpec:
        normalized = _normalize_route(route)
        if normalized != self.selected.webhook_path:
            raise KeyError(normalized)
        return self.selected

    def get(self, name: str) -> WorkflowSpec:
        return self._by_name[name]


def _workflow_spec(path: Path, raw: str, data: dict[str, Any]) -> WorkflowSpec:
    if not isinstance(data, dict):
        raise ValueError(f"workflow file {str(path)!r} must contain a JSON object")

    name = _string_or(path.stem, data.get("name"))
    workflow_id = _string_or(path.stem, data.get("id"))
    nodes = data.get("nodes")
    if not isinstance(nodes, list):
        nodes = []

    webhook_node = next(
        (
            node
            for node in nodes
            if isinstance(node, dict) and node.get("type") == "n8n-nodes-base.webhook"
        ),
        None,
    )
    webhook_path = ""
    if webhook_node is not None:
        parameters = webhook_node.get("parameters")
        if isinstance(parameters, dict):
            webhook_path = _normalize_route(parameters.get("path", ""))

    prompt_messages: list[str] = []
    chain_llm_count = 0
    for node in nodes:
        if not isinstance(node, dict):
            continue
        if node.get("type") != "@n8n/n8n-nodes-langchain.chainLlm":
            continue
        chain_llm_count += 1
        parameters = node.get("parameters")
        if not isinstance(parameters, dict):
            continue
        messages = parameters.get("messages")
        if not isinstance(messages, dict):
            continue
        values = messages.get("messageValues")
        if not isinstance(values, list):
            continue
        for entry in values:
            if not isinstance(entry, dict):
                continue
            message = entry.get("message")
            if not isinstance(message, str):
                continue
            cleaned = message.removeprefix("=").strip()
            if cleaned:
                prompt_messages.append(cleaned)

    parser_schema: dict[str, Any] = {}
    for node in nodes:
        if not isinstance(node, dict):
            continue
        if node.get("type") != "@n8n/n8n-nodes-langchain.outputParserStructured":
            continue
        parameters = node.get("parameters")
        if not isinstance(parameters, dict):
            continue
        raw_schema = parameters.get("inputSchema")
        if isinstance(raw_schema, str) and raw_schema.strip():
            parsed = json.loads(raw_schema)
            if isinstance(parsed, dict):
                parser_schema = parsed
        elif isinstance(raw_schema, dict):
            parser_schema = deepcopy(raw_schema)
        break

    declared_models = tuple(sorted(_collect_declared_models(nodes)))
    prompt = "\n\n".join(prompt_messages)
    return WorkflowSpec(
        workflow_id=workflow_id,
        name=name,
        webhook_path=webhook_path,
        prompt=prompt,
        parser_schema=parser_schema,
        source_path=path,
        workflow_sha256=sha256_text(raw),
        prompt_sha256=sha256_text(prompt),
        declared_models=declared_models,
        chain_llm_count=chain_llm_count,
        public_workflow=_public_workflow_fields(name, workflow_id, webhook_node, webhook_path),
    )


def _collect_declared_models(nodes: list[Any]) -> set[str]:
    models: set[str] = set()
    for node in nodes:
        if not isinstance(node, dict):
            continue
        parameters = node.get("parameters")
        if not isinstance(parameters, dict):
            continue
        model = parameters.get("model")
        if isinstance(model, str):
            cleaned = model.strip()
            if cleaned:
                models.add(cleaned)
        elif isinstance(model, dict):
            for key in ("value", "cachedResultName", "name"):
                value = model.get(key)
                if isinstance(value, str) and value.strip():
                    models.add(value.strip())
    return models


def _public_workflow(spec: WorkflowSpec, *, active: bool) -> dict[str, Any]:
    workflow = deepcopy(spec.public_workflow)
    workflow["active"] = active
    return workflow


def _public_workflow_fields(
    name: str,
    workflow_id: str,
    webhook_node: dict[str, Any] | None,
    webhook_path: str,
) -> dict[str, Any]:
    node_name = "Webhook"
    node_id = f"{workflow_id}-webhook"
    node_type = "n8n-nodes-base.webhook"
    node_type_version: float | int = 2
    node_position: list[Any] | None = None
    http_method = "POST"
    response_mode = "responseNode"
    options: dict[str, Any] = {}

    if isinstance(webhook_node, dict):
        node_name = _string_or(node_name, webhook_node.get("name"))
        node_id = _string_or(node_id, webhook_node.get("id"))
        node_type = _string_or(node_type, webhook_node.get("type"))
        node_type_version = webhook_node.get("typeVersion", node_type_version)
        position = webhook_node.get("position")
        if isinstance(position, list):
            node_position = deepcopy(position)
        parameters = webhook_node.get("parameters")
        if isinstance(parameters, dict):
            http_method = _string_or(http_method, parameters.get("httpMethod"))
            response_mode = _string_or(response_mode, parameters.get("responseMode"))
            raw_options = parameters.get("options")
            if isinstance(raw_options, dict):
                options = deepcopy(raw_options)

    node: dict[str, Any] = {
        "parameters": {
            "httpMethod": http_method,
            "path": webhook_path,
            "responseMode": response_mode,
            "options": options,
        },
        "type": node_type,
        "typeVersion": node_type_version,
        "id": node_id,
        "name": node_name,
    }
    if node_position is not None:
        node["position"] = node_position
    return {"id": workflow_id, "name": name, "active": False, "nodes": [node]}


def _normalize_route(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    return value.strip().lstrip("/").lstrip("=")


def _string_or(default: str, value: Any) -> str:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return default
