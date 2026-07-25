"""Loopback-only dual-surface HTTP server for fair Bastet A/B experiments."""

from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from .budget import BudgetAuthority
from .contracts import (
    AIS3_PINNED_MODEL,
    AutomationError,
    BudgetExceeded,
    BudgetLimits,
    ConfigurationMismatch,
    GatewayProfile,
    ModelMismatch,
    ProviderPermanentError,
    UnsupportedWorkflow,
)
from .executions import ExecutionStore
from .gateway import Gateway
from .ledger import Ledger, ensure_manifest
from .provider import AIS3Provider, MockProvider
from .registry import WorkflowRegistry
from .surfaces.n8n import N8NSurface
from .surfaces.openai import OpenAISurface

MAX_REQUEST_BYTES = 4 * 1024 * 1024
LOOPBACK_HOSTS = {"127.0.0.1", "localhost"}


@dataclass
class AutomationService:
    profile: GatewayProfile
    registry: WorkflowRegistry
    budget: BudgetAuthority
    ledger: Ledger
    gateway: Gateway
    openai: OpenAISurface
    n8n: N8NSurface
    executions: ExecutionStore
    manifest: dict[str, Any]

    def health(self) -> dict[str, Any]:
        return {
            "status": "ok",
            "experiment_id": self.profile.experiment_id,
            "subject_id": self.profile.subject_id,
            "provider_mode": self.profile.provider_mode,
            "model": AIS3_PINNED_MODEL,
            "workflow": self.profile.selected_workflow,
            "claim_level": self.manifest["claim_level"],
        }

    def close(self) -> None:
        self.gateway.close()


def build_service(
    *,
    workflow_root: Path,
    experiment_id: str,
    subject_id: str,
    budget_limits: BudgetLimits,
    ledger_path: Path,
    manifest_path: Path,
    execution_path: Path | None = None,
    selected_workflow: str = "flashloan",
    live: bool = False,
    api_key: str | None = None,
    max_provider_attempts: int = 3,
) -> AutomationService:
    registry = WorkflowRegistry.load(workflow_root, selected=selected_workflow)
    workflow = registry.selected
    profile = GatewayProfile(
        experiment_id=experiment_id,
        subject_id=subject_id,
        provider_mode="live" if live else "mock",
        selected_workflow=workflow.name,
        workflow_sha256=workflow.workflow_sha256,
        prompt_sha256=workflow.prompt_sha256,
        budget=budget_limits,
    )
    manifest = ensure_manifest(manifest_path, profile)
    ledger = Ledger(ledger_path)
    budget = BudgetAuthority(budget_limits, prior_records=ledger.records())
    executions = ExecutionStore(
        execution_path or Path(manifest_path).parent / "executions.jsonl"
    )
    if live:
        key = api_key or os.environ.get("AIS3_API_KEY")
        if not key:
            raise ValueError("live mode requires AIS3_API_KEY in the process environment")
        provider = AIS3Provider(api_key=key)
    else:
        provider = MockProvider()
    gateway = Gateway(
        profile=profile,
        budget=budget,
        ledger=ledger,
        provider=provider,
        max_attempts=max_provider_attempts,
    )
    return AutomationService(
        profile=profile,
        registry=registry,
        budget=budget,
        ledger=ledger,
        gateway=gateway,
        openai=OpenAISurface(gateway),
        n8n=N8NSurface(registry, gateway, executions),
        executions=executions,
        manifest=manifest,
    )


def _handler(service: AutomationService):
    class Handler(BaseHTTPRequestHandler):
        server_version = "BastetAutomation/1"
        protocol_version = "HTTP/1.1"

        def log_message(self, _format: str, *_args: Any) -> None:
            # BaseHTTPRequestHandler logs raw request lines. Suppress them so a
            # caller cannot smuggle credential-shaped material into stdout.
            return

        def _headers(self) -> dict[str, str]:
            return {str(k): str(v) for k, v in self.headers.items()}

        def _json_body(self) -> dict[str, Any]:
            raw_length = self.headers.get("Content-Length")
            if raw_length is None:
                raise ValueError("Content-Length is required")
            try:
                length = int(raw_length)
            except ValueError as exc:
                raise ValueError("invalid Content-Length") from exc
            if length <= 0 or length > MAX_REQUEST_BYTES:
                raise ValueError(f"request body must be 1..{MAX_REQUEST_BYTES} bytes")
            raw = self.rfile.read(length)
            try:
                value = json.loads(raw)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValueError("request body is not valid JSON") from exc
            if not isinstance(value, dict):
                raise ValueError("request body must be a JSON object")
            return value

        def _send_json(self, status: int, payload: Any) -> None:
            body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _send_text(self, status: int, value: str) -> None:
            body = value.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _error(self, exc: Exception) -> None:
            if isinstance(exc, ConfigurationMismatch):
                status = 409
            elif isinstance(exc, BudgetExceeded):
                status = 429
            elif isinstance(exc, (ProviderPermanentError, UnsupportedWorkflow)):
                status = 422
            elif isinstance(exc, (ModelMismatch, AutomationError, ValueError)):
                status = 400
            elif isinstance(exc, KeyError):
                status = 404
            else:
                status = 500
            safe_message = str(exc) if status < 500 else "internal automation error"
            self._send_json(
                status,
                {"error": {"type": type(exc).__name__, "message": safe_message}},
            )

        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            try:
                path = urlparse(self.path).path
                if path == "/health":
                    self._send_json(200, service.health())
                elif path == "/manifest":
                    self._send_json(200, service.manifest)
                elif path == "/budget":
                    self._send_json(
                        200,
                        {
                            "budget": service.budget.snapshot(),
                            "ledger": service.ledger.summary(),
                        },
                    )
                elif path == "/v1/models":
                    self._send_json(200, service.openai.models_payload())
                elif path == "/api/v1/workflows":
                    self._send_json(200, service.n8n.workflows_payload())
                elif path.startswith("/api/v1/executions/"):
                    execution_id = unquote(path.rsplit("/", 1)[-1])
                    self._send_json(200, service.n8n.execution_payload(execution_id))
                else:
                    raise KeyError("route not found")
            except Exception as exc:  # response boundary
                self._error(exc)

        def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            try:
                path = urlparse(self.path).path
                payload = self._json_body()
                if path == "/v1/chat/completions":
                    self._send_json(
                        200, service.openai.complete(payload, self._headers())
                    )
                elif path.startswith("/webhook/"):
                    webhook_path = unquote(path[len("/webhook/") :])
                    execution_id = service.n8n.submit(
                        webhook_path, payload, self._headers()
                    )
                    self._send_text(200, execution_id)
                else:
                    raise KeyError("route not found")
            except Exception as exc:  # response boundary
                self._error(exc)

    return Handler


def create_server(
    service: AutomationService,
    *,
    host: str = "127.0.0.1",
    port: int = 8765,
) -> ThreadingHTTPServer:
    if host not in LOOPBACK_HOSTS:
        raise ValueError("Phase 1 automation server may bind only to loopback")
    if not isinstance(port, int) or isinstance(port, bool) or not 0 <= port <= 65535:
        raise ValueError("port must be between 0 and 65535")
    server = ThreadingHTTPServer((host, port), _handler(service))
    server.daemon_threads = True
    return server


class RunningServer:
    """Test-friendly context manager for an in-process automation service."""

    def __init__(
        self,
        service: AutomationService,
        host: str = "127.0.0.1",
        port: int = 0,
    ) -> None:
        self.service = service
        self.server = create_server(service, host=host, port=port)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        host, port = self.server.server_address[:2]
        return f"http://{host}:{port}"

    def __enter__(self) -> "RunningServer":
        self.thread.start()
        return self

    def __exit__(self, *_args: Any) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.service.close()
