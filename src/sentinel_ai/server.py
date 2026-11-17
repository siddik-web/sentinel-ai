"""Lightweight HTTP REST API Server for Sentinel AI web dashboard, webhook ingestion, and metrics.

Run with ``python -m sentinel_ai.server`` or ``sentinel-ai serve``. Configuration is read from
``SENTINEL_*`` environment variables (see ``build_state_from_env``).
"""

import hmac
import json
import logging
import os
import signal
import threading
import time
from collections.abc import Mapping
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from sentinel_ai.agents.orchestrator import OrchestratorAgent
from sentinel_ai.audit.logger import CryptographicAuditLogger
from sentinel_ai.core.ocsf.models import OCSFBaseEvent
from sentinel_ai.exceptions import (
    AuditIntegrityError,
    OCSFValidationError,
    PolicyViolationError,
    SentinelError,
    TicketNotFoundError,
    TicketStateError,
)
from sentinel_ai.hitl.notifier import HITLWebhookNotifier
from sentinel_ai.ingestion.engine import IngestionEngine
from sentinel_ai.ingress.webhook import WebhookAdapter
from sentinel_ai.persistence.state_store import HITL_APPROVED, HITL_REJECTED, StateStore
from sentinel_ai.providers.base import LLMProvider
from sentinel_ai.providers.factory import create_provider_from_env
from sentinel_ai.response.base import ResponseAdapter
from sentinel_ai.response.edr import EDRResponseAdapter
from sentinel_ai.response.identity import IdentityResponseAdapter
from sentinel_ai.security.pep import PolicyEnforcementPoint
from sentinel_ai.security.policy_rules import PolicyRuleEngine
from sentinel_ai.telemetry.metrics import MetricsCollector

logger = logging.getLogger("sentinel_ai.server")

MAX_REQUEST_BODY_BYTES = 1_048_576
MANUAL_REVIEW_ACTION = "MANUAL_REVIEW"
RESPONSE_AGENT_ID = "response-agent-01"
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


class SentinelServerState:
    """Shared state for a Sentinel AI server instance: wiring of all platform components."""

    def __init__(
        self,
        db_path: str = "sentinel_ai.db",
        rule_engine: PolicyRuleEngine | None = None,
        llm_provider: LLMProvider | None = None,
        hitl_notifier: HITLWebhookNotifier | None = None,
        api_token: str | None = None,
    ):
        self.api_token = api_token or None
        self.state_store = StateStore(db_path=db_path)
        self.metrics = MetricsCollector()

        # The audit chain resumes from persisted entries and writes through to the store
        # before each entry is accepted, so the chain survives restarts intact.
        self.audit_logger = CryptographicAuditLogger(
            sink=self.state_store.save_audit_entry,
            entries=self.state_store.load_audit_entries(),
        )
        self.pep = PolicyEnforcementPoint(
            audit_logger=self.audit_logger,
            rule_engine=rule_engine,
            on_decision=self.metrics.record_policy_decision,
        )
        self.orchestrator = OrchestratorAgent(pep=self.pep, llm_provider=llm_provider)
        self.ingestion_engine = IngestionEngine()
        self.webhook_adapter = WebhookAdapter()
        self.hitl_notifier = hitl_notifier

        # Response Adapters
        self.edr_adapter = EDRResponseAdapter(pep=self.pep)
        self.identity_adapter = IdentityResponseAdapter(pep=self.pep)
        self._response_adapters: dict[str, ResponseAdapter] = {
            "ISOLATE_HOST": self.edr_adapter,
            "TERMINATE_PROCESS": self.edr_adapter,
            "REVOKE_CREDENTIALS": self.identity_adapter,
            "BLOCK_IP": self.identity_adapter,
        }

        self._lock = threading.RLock()

        # Wire ingestion engine
        self.ingestion_engine.subscribe(self._handle_ingested_event)

    # --- Ingestion and triage workflow ---

    def ingest_payload(self, raw_payload: dict[str, Any]) -> tuple[OCSFBaseEvent, bool]:
        """Normalize a raw webhook payload and run it through the workflow.

        Returns:
            The normalized event and whether it was processed (False if deduplicated).

        Raises:
            OCSFValidationError: If the payload cannot be normalized to an OCSF event.
        """
        event = self.webhook_adapter.parse_and_normalize(raw_payload)
        return event, self.ingest_event(event)

    def ingest_event(self, event: OCSFBaseEvent) -> bool:
        """Route an OCSF event to the agent workflow unless it is a duplicate."""
        with self._lock:
            # Durable deduplication: an event already recorded is never re-processed,
            # including after a restart.
            if self.state_store.get_workflow(event.get_event_id()) is not None:
                return False
            return self.ingestion_engine.process_event(event)

    def _handle_ingested_event(self, ocsf_event: OCSFBaseEvent) -> None:
        event_id = ocsf_event.get_event_id()
        store = self.state_store

        store.record_workflow_transition(
            event_id, "received", {"event": ocsf_event.model_dump(mode="json")}
        )
        self.audit_logger.log_event(
            "EVENT_RECEIVED",
            "ingestion",
            {"event_id": event_id, "event": ocsf_event.model_dump(mode="json")},
        )
        self.metrics.record_ingest()

        store.record_workflow_transition(event_id, "triage_in_progress")
        started = time.monotonic()
        try:
            summary = self.orchestrator.process_event_workflow(ocsf_event)
        except PolicyViolationError as e:
            # A policy denial halts the workflow and escalates to a human; it never proceeds.
            self.metrics.record_triage(time.monotonic() - started)
            reason = f"Workflow halted by policy rule '{e.rule}': {e!s}"
            self.audit_logger.log_event(
                "WORKFLOW_HALTED", "orchestrator", {"event_id": event_id, "rule": e.rule}
            )
            self._escalate(event_id, MANUAL_REVIEW_ACTION, {"reason": reason, "rule": e.rule})
            return
        except Exception as e:
            self.metrics.record_workflow_failure()
            store.record_workflow_transition(event_id, "failed", {"error": str(e)})
            self.audit_logger.log_event(
                "WORKFLOW_FAILED", "orchestrator", {"event_id": event_id, "error": str(e)}
            )
            logger.exception("workflow failed", extra={"event_id": event_id})
            raise

        self.metrics.record_triage(time.monotonic() - started)
        summary_data = summary.model_dump(mode="json")
        self.audit_logger.log_event("TRIAGE_OUTPUT", "orchestrator", summary_data)

        if summary.requires_hitl:
            action_info = dict(summary.suggested_actions)
            action_name = action_info.get("action") or MANUAL_REVIEW_ACTION
            action_info["reason"] = summary.triage_response.recommendation
            action_info["severity"] = summary.triage_response.severity_assessment
            self._escalate(event_id, action_name, action_info, summary_data)
        else:
            store.record_workflow_transition(
                event_id, "completed", {"outcome": "triaged", "summary": summary_data}
            )

    def _escalate(
        self,
        event_id: str,
        action_name: str,
        parameters: dict[str, Any],
        summary_data: dict[str, Any] | None = None,
    ) -> None:
        """Create a HITL ticket, pause the workflow, and notify the operator channel."""
        ticket_id = f"TICKET-{event_id}"
        ticket = self.state_store.create_hitl_ticket(
            ticket_id=ticket_id, event_id=event_id, action_name=action_name, parameters=parameters
        )
        self.metrics.record_hitl_created()
        self.state_store.record_workflow_transition(
            event_id, "paused_hitl", {"ticket_id": ticket_id, "summary": summary_data}
        )
        self.audit_logger.log_event(
            "HITL_TICKET_CREATED",
            "orchestrator",
            {"ticket_id": ticket_id, "event_id": event_id, "action": action_name},
        )

        if self.hitl_notifier is not None:
            delivered, detail = self.hitl_notifier.notify(ticket)
            self.audit_logger.log_event(
                "HITL_NOTIFICATION_DELIVERED" if delivered else "HITL_NOTIFICATION_FAILED",
                "hitl-interface",
                {"ticket_id": ticket_id, "detail": detail},
            )
            if not delivered:
                self.metrics.record_hitl_delivery_failure()
                logger.error(
                    "HITL notification delivery failed",
                    extra={"ticket_id": ticket_id, "detail": detail},
                )

    # --- HITL decisions ---

    def decide_ticket(
        self, ticket_id: str, approve: bool, decided_by: str = "operator"
    ) -> dict[str, Any]:
        """Record an operator decision on a pending ticket and act on it.

        Approval executes the ticket's response action through the PEP with HITL approval.
        Rejection dismisses the workflow without action.

        Raises:
            TicketNotFoundError: If the ticket does not exist.
            TicketStateError: If the ticket has already been decided.
        """
        with self._lock:
            ticket = self.state_store.get_hitl_ticket(ticket_id)
            if ticket is None:
                raise TicketNotFoundError(f"Ticket '{ticket_id}' not found.")
            if ticket["status"] != "PENDING":
                raise TicketStateError(
                    f"Ticket '{ticket_id}' is already {ticket['status']} and cannot be decided again."
                )

            event_id = ticket["event_id"]
            action_name = ticket["action_name"]
            decision = HITL_APPROVED if approve else HITL_REJECTED

            # Write-before-act: the decision is audited before anything is executed.
            self.audit_logger.log_event(
                "HITL_DECISION",
                decided_by,
                {"ticket_id": ticket_id, "decision": decision, "action": action_name},
            )
            self.state_store.decide_hitl_ticket(ticket_id, decision, decided_by)

            if not approve:
                self.metrics.record_hitl_rejected()
                self.state_store.record_workflow_transition(
                    event_id, "completed", {"outcome": "dismissed", "decided_by": decided_by}
                )
                return self.state_store.get_hitl_ticket(ticket_id)

            self.metrics.record_hitl_approved()
            adapter = self._response_adapters.get(action_name)
            if adapter is None:
                # Review-only ticket: nothing to execute.
                self.state_store.record_workflow_transition(
                    event_id, "completed", {"outcome": "acknowledged", "decided_by": decided_by}
                )
                return self.state_store.get_hitl_ticket(ticket_id)

            self.state_store.record_workflow_transition(
                event_id, "response_in_progress", {"action": action_name}
            )
            try:
                result = adapter.execute_action(
                    agent_id=RESPONSE_AGENT_ID,
                    action_name=action_name,
                    parameters=ticket["parameters"],
                    hitl_approved=True,
                ).model_dump(mode="json")
            except SentinelError as e:
                result = {"action_name": action_name, "success": False, "message": str(e)}

            self.metrics.record_response_action(result["success"])
            self.state_store.set_hitl_execution_result(ticket_id, result)
            self.audit_logger.log_event(
                "RESPONSE_EXECUTED" if result["success"] else "RESPONSE_FAILED",
                RESPONSE_AGENT_ID,
                {"ticket_id": ticket_id, "result": result},
            )
            self.state_store.record_workflow_transition(
                event_id,
                "completed" if result["success"] else "failed",
                {"outcome": "responded" if result["success"] else "response_failed", **result},
            )
            return self.state_store.get_hitl_ticket(ticket_id)

    # --- Audit ---

    def verify_persisted_audit(self) -> tuple[bool, int, str | None]:
        """Verify the durable audit chain. Returns ``(valid, entry_count, error)``."""
        entries = self.state_store.load_audit_entries()
        try:
            CryptographicAuditLogger.verify_entries(entries)
        except AuditIntegrityError as e:
            return False, len(entries), str(e)
        return True, len(entries), None


class SentinelRequestHandler(BaseHTTPRequestHandler):
    """HTTP Request handler for Sentinel AI REST API endpoints and Web Console."""

    server_state: SentinelServerState = None
    server_version = "SentinelAI"
    sys_version = ""

    def log_message(self, format: str, *args: Any) -> None:
        logger.info("http %s", format % args)

    def _send_bytes(self, status_code: int, content_type: str, data: bytes) -> None:
        self.send_response(status_code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _send_json(self, status_code: int, data: dict[str, Any]) -> None:
        self._send_bytes(status_code, "application/json", json.dumps(data).encode("utf-8"))

    def _authorized(self) -> bool:
        """Check the bearer token for API routes when one is configured."""
        token = self.server_state.api_token
        if not token:
            return True
        supplied = self.headers.get("Authorization", "")
        return hmac.compare_digest(supplied.encode("utf-8"), f"Bearer {token}".encode())

    def _require_auth(self) -> bool:
        if self._authorized():
            return True
        self.send_response(401)
        self.send_header("WWW-Authenticate", "Bearer")
        body = json.dumps({"error": "Missing or invalid bearer token"}).encode("utf-8")
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        return False

    @staticmethod
    def _int_param(query: dict[str, list[str]], name: str, default: int, maximum: int) -> int:
        try:
            return max(1, min(maximum, int(query.get(name, [default])[0])))
        except ValueError:
            return default

    def do_GET(self) -> None:
        url = urlsplit(self.path)
        path = url.path
        query = parse_qs(url.query)
        state = self.server_state

        if path in ("/", "/index.html"):
            dashboard_file = Path(__file__).parent / "dashboard" / "index.html"
            if dashboard_file.exists():
                self._send_bytes(200, "text/html; charset=utf-8", dashboard_file.read_bytes())
            else:
                self._send_json(404, {"error": "Dashboard HTML not found"})
            return

        if path == "/healthz":
            self._send_json(200, {"status": "ok"})
            return

        if path == "/metrics":
            metrics_str = state.metrics.generate_prometheus_metrics()
            self._send_bytes(200, "text/plain; version=0.0.4", metrics_str.encode("utf-8"))
            return

        if not path.startswith("/api/"):
            self._send_json(404, {"error": "Endpoint not found"})
            return
        if not self._require_auth():
            return

        if path == "/api/v1/stats":
            self._send_json(200, state.metrics.get_stats())

        elif path == "/api/v1/hitl":
            status_filter = query.get("status", [None])[0]
            tickets = state.state_store.list_hitl_tickets(status_filter=status_filter)
            self._send_json(200, {"status": "success", "tickets": tickets})

        elif path == "/api/v1/workflows":
            limit = self._int_param(query, "limit", 50, 500)
            workflows = state.state_store.list_workflows(limit=limit)
            self._send_json(200, {"status": "success", "workflows": workflows})

        elif path == "/api/v1/audit":
            limit = self._int_param(query, "limit", 50, 1000)
            entries = state.audit_logger.entries
            self._send_json(
                200,
                {
                    "status": "success",
                    "total_entries": len(entries),
                    "entries": [e.model_dump() for e in entries[-limit:]],
                },
            )

        elif path == "/api/v1/audit/verify":
            is_valid, total, error = state.verify_persisted_audit()
            self._send_json(
                200,
                {
                    "status": "success",
                    "hash_chain_valid": is_valid,
                    "total_entries": total,
                    "error": error,
                },
            )
        else:
            self._send_json(404, {"error": "Endpoint not found"})

    def _read_json_object(self) -> dict[str, Any] | None:
        """Read and parse the request body; sends the error response and returns None on failure."""
        try:
            content_length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            content_length = -1
        if content_length < 0:
            self._send_json(400, {"error": "Invalid Content-Length"})
            return None
        if content_length > MAX_REQUEST_BODY_BYTES:
            self.close_connection = True  # the unread body must not be parsed as a request
            self._send_json(413, {"error": "Request body too large"})
            return None

        body = self.rfile.read(content_length) if content_length > 0 else b"{}"
        try:
            payload = json.loads(body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._send_json(400, {"error": "Invalid JSON payload"})
            return None
        if not isinstance(payload, dict):
            self._send_json(400, {"error": "JSON payload must be an object"})
            return None
        return payload

    def do_POST(self) -> None:
        path = urlsplit(self.path).path
        state = self.server_state

        if path not in ("/api/v1/webhook", "/api/v1/hitl/approve", "/api/v1/hitl/reject"):
            self._send_json(404, {"error": "Endpoint not found"})
            return
        if not self._require_auth():
            return
        payload = self._read_json_object()
        if payload is None:
            return

        if path == "/api/v1/webhook":
            try:
                event, processed = state.ingest_payload(payload)
            except OCSFValidationError as e:
                self._send_json(400, {"error": str(e)})
                return
            except Exception:
                logger.exception("webhook ingestion failed")
                self._send_json(500, {"error": "Internal error while processing event"})
                return
            self._send_json(
                200,
                {"status": "success", "event_id": event.get_event_id(), "processed": processed},
            )
            return

        ticket_id = payload.get("ticket_id")
        if not ticket_id or not isinstance(ticket_id, str):
            self._send_json(400, {"error": "Missing required field 'ticket_id'"})
            return
        decided_by = str(payload.get("approver") or "operator")[:200]
        approve = path.endswith("/approve")

        try:
            ticket = state.decide_ticket(ticket_id, approve=approve, decided_by=decided_by)
        except TicketNotFoundError:
            self._send_json(404, {"error": "Ticket ID not found"})
            return
        except TicketStateError as e:
            self._send_json(409, {"error": str(e)})
            return
        except Exception:
            logger.exception("HITL decision failed", extra={"ticket_id": ticket_id})
            self._send_json(500, {"error": "Internal error while recording decision"})
            return

        self._send_json(
            200,
            {
                "status": "success",
                "ticket_id": ticket_id,
                "approval_status": ticket["status"],
                "execution_result": ticket["execution_result"],
            },
        )


def create_sentinel_server(
    host: str = "127.0.0.1",
    port: int = 8000,
    db_path: str = ":memory:",
    server_state: SentinelServerState | None = None,
    **state_kwargs: Any,
) -> ThreadingHTTPServer:
    """Factory creating a configured Sentinel AI HTTP server instance.

    Pass ``server_state`` to serve an existing state, or ``db_path`` plus any
    ``SentinelServerState`` keyword arguments to build one. The state is available as
    ``server.server_state``.
    """
    if server_state is None:
        server_state = SentinelServerState(db_path=db_path, **state_kwargs)
    # Each server gets its own handler class so multiple servers never share state.
    handler_class = type("BoundSentinelRequestHandler", (SentinelRequestHandler,), {})
    handler_class.server_state = server_state
    server = ThreadingHTTPServer((host, port), handler_class)
    server.daemon_threads = True
    server.server_state = server_state
    return server


def build_state_from_env(
    env: Mapping[str, str] | None = None, db_path: str | None = None
) -> SentinelServerState:
    """Build server state from ``SENTINEL_*`` environment variables.

    - ``SENTINEL_DB_PATH``: SQLite database path (default ``sentinel_ai.db``).
    - ``SENTINEL_POLICY_FILE``: JSON policy file adding restrictions to the built-in policy.
    - ``SENTINEL_API_TOKEN``: bearer token required on ``/api/*`` routes when set.
    - ``SENTINEL_HITL_WEBHOOK_URL``: URL that receives a POST for each HITL escalation.
    - ``SENTINEL_LLM_*``: see ``sentinel_ai.providers.factory.create_provider_from_env``.

    Raises:
        SentinelError: If the configuration is invalid.
    """
    env = os.environ if env is None else env
    policy_file = env.get("SENTINEL_POLICY_FILE")
    webhook_url = env.get("SENTINEL_HITL_WEBHOOK_URL")
    return SentinelServerState(
        db_path=db_path or env.get("SENTINEL_DB_PATH", "sentinel_ai.db"),
        rule_engine=PolicyRuleEngine.from_file(policy_file) if policy_file else None,
        llm_provider=create_provider_from_env(env),
        hitl_notifier=HITLWebhookNotifier(webhook_url) if webhook_url else None,
        api_token=env.get("SENTINEL_API_TOKEN"),
    )


class _JsonLogFormatter(logging.Formatter):
    """Formats log records as single-line JSON for machine parsing."""

    _STANDARD = set(logging.LogRecord("", 0, "", 0, "", (), None).__dict__) | {"message", "asctime"}

    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "component": record.name,
            "message": record.getMessage(),
        }
        entry.update({k: v for k, v in record.__dict__.items() if k not in self._STANDARD})
        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry, default=str)


def configure_logging() -> None:
    """Send structured JSON logs to stderr."""
    handler = logging.StreamHandler()
    handler.setFormatter(_JsonLogFormatter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(os.environ.get("SENTINEL_LOG_LEVEL", "INFO").upper())


def run_server(host: str | None = None, port: int | None = None, db_path: str | None = None) -> int:
    """Start the server and block until interrupted. Returns a process exit code."""
    configure_logging()
    host = host or os.environ.get("SENTINEL_HOST", "127.0.0.1")
    try:
        port = port if port is not None else int(os.environ.get("SENTINEL_PORT", "8000"))
        state = build_state_from_env(db_path=db_path)
    except (SentinelError, ValueError) as e:
        logger.error("invalid configuration: %s", e)
        return 2

    valid, total, error = state.verify_persisted_audit()
    if not valid:
        logger.error("persisted audit chain failed verification: %s", error)
    if host not in LOOPBACK_HOSTS and not state.api_token:
        logger.warning(
            "listening on a non-loopback address without SENTINEL_API_TOKEN; "
            "the API accepts unauthenticated requests"
        )

    server = create_sentinel_server(host=host, port=port, server_state=state)
    signal.signal(
        signal.SIGTERM, lambda *_: threading.Thread(target=server.shutdown, daemon=True).start()
    )
    logger.info(
        "sentinel server started",
        extra={
            "host": host,
            "port": server.server_address[1],
            "db_path": state.state_store.db_path,
            "audit_entries": total,
            "auth_enabled": bool(state.api_token),
            "llm_provider": type(state.orchestrator.triage_agent.llm_provider).__name__,
            "policy_file": os.environ.get("SENTINEL_POLICY_FILE"),
        },
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        state.state_store.close()
        logger.info("sentinel server stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(run_server())
