"""Lightweight HTTP REST API Server for Sentinel AI webhook ingestion and HITL approvals."""

import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

from sentinel_ai.agents.orchestrator import OrchestratorAgent
from sentinel_ai.audit.logger import CryptographicAuditLogger
from sentinel_ai.ingestion.engine import IngestionEngine
from sentinel_ai.ingress.webhook import WebhookAdapter
from sentinel_ai.persistence.state_store import StateStore
from sentinel_ai.response.edr import EDRResponseAdapter
from sentinel_ai.response.identity import IdentityResponseAdapter
from sentinel_ai.security.pep import PolicyEnforcementPoint


class SentinelServerState:
    """Shared singleton state for Sentinel AI server instance."""

    def __init__(self, db_path: str = "sentinel_ai.db"):
        self.state_store = StateStore(db_path=db_path)
        self.audit_logger = CryptographicAuditLogger()
        self.pep = PolicyEnforcementPoint(audit_logger=self.audit_logger)
        self.orchestrator = OrchestratorAgent(pep=self.pep)
        self.ingestion_engine = IngestionEngine()
        self.webhook_adapter = WebhookAdapter()

        # Response Adapters
        self.edr_adapter = EDRResponseAdapter(pep=self.pep)
        self.identity_adapter = IdentityResponseAdapter(pep=self.pep)

        # Wire ingestion engine
        self.ingestion_engine.subscribe(self._handle_ingested_event)

    def _handle_ingested_event(self, ocsf_event):
        summary = self.orchestrator.process_event_workflow(ocsf_event)
        # If HITL required, store ticket
        if summary.requires_hitl:
            ticket_id = f"TICKET-{summary.event_id}"
            action_info = summary.suggested_actions
            action_name = action_info.get("action", "UNKNOWN_ACTION")
            self.state_store.create_hitl_ticket(
                ticket_id=ticket_id,
                event_id=summary.event_id,
                action_name=action_name,
                parameters=action_info,
            )

        # Save audit entries into persistent state store
        for entry in self.audit_logger.entries:
            self.state_store.save_audit_entry(entry)


class SentinelRequestHandler(BaseHTTPRequestHandler):
    """HTTP Request handler for Sentinel AI REST API endpoints."""

    server_state: SentinelServerState = None

    def _send_json(self, status_code: int, data: dict[str, Any]):
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))

    def do_GET(self):
        if self.path == "/api/v1/hitl":
            tickets = self.server_state.state_store.list_hitl_tickets()
            self._send_json(200, {"status": "success", "tickets": tickets})
        elif self.path == "/api/v1/audit/verify":
            is_valid = self.server_state.audit_logger.verify_chain_integrity()
            entries = [e.model_dump() for e in self.server_state.state_store.load_audit_entries()]
            self._send_json(
                200,
                {
                    "status": "success",
                    "hash_chain_valid": is_valid,
                    "total_entries": len(entries),
                },
            )
        else:
            self._send_json(404, {"error": "Endpoint not found"})

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b"{}"

        try:
            payload = json.loads(body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._send_json(400, {"error": "Invalid JSON payload"})
            return

        if self.path == "/api/v1/webhook":
            try:
                event = self.server_state.webhook_adapter.parse_and_normalize(payload)
                processed = self.server_state.ingestion_engine.process_event(event)
                self._send_json(
                    200,
                    {
                        "status": "success",
                        "event_id": event.get_event_id(),
                        "processed": processed,
                    },
                )
            except Exception as e:  # noqa: BLE001
                self._send_json(400, {"error": str(e)})

        elif self.path == "/api/v1/hitl/approve":
            ticket_id = payload.get("ticket_id")
            if not ticket_id:
                self._send_json(400, {"error": "Missing required field 'ticket_id'"})
                return

            updated = self.server_state.state_store.update_hitl_ticket_status(ticket_id, "APPROVED")
            if not updated:
                self._send_json(404, {"error": "Ticket ID not found"})
                return

            self._send_json(
                200, {"status": "success", "ticket_id": ticket_id, "approval_status": "APPROVED"}
            )
        else:
            self._send_json(404, {"error": "Endpoint not found"})


def create_sentinel_server(
    host: str = "127.0.0.1", port: int = 8000, db_path: str = ":memory:"
) -> HTTPServer:
    """Factory creating a configured Sentinel AI HTTP server instance."""
    server_state = SentinelServerState(db_path=db_path)
    handler_class = SentinelRequestHandler
    handler_class.server_state = server_state
    server = HTTPServer((host, port), handler_class)
    return server
