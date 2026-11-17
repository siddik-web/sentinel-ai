"""Tests for HITL decisions, response execution, workflow state, and notifications."""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from sentinel_ai.exceptions import SentinelError, TicketNotFoundError, TicketStateError
from sentinel_ai.hitl.notifier import HITLWebhookNotifier
from sentinel_ai.server import SentinelServerState

FINDING = {
    "class_uid": 2001,
    "activity_id": 7,
    "severity_id": 5,
    "time": 1710000000,
    "title": "Ransomware",
    "analytic_name": "EDR-1",
    "confidence_score": 0.99,
    "device_hostname": "wks-01",
}


def _ingest(state, payload=None):
    event, _ = state.ingest_payload(payload or FINDING)
    event_id = event.get_event_id()
    return event_id, f"TICKET-{event_id}"


def test_approval_executes_response_action_and_completes_workflow():
    state = SentinelServerState(db_path=":memory:")
    event_id, ticket_id = _ingest(state)
    assert state.state_store.get_workflow(event_id)["status"] == "paused_hitl"

    ticket = state.decide_ticket(ticket_id, approve=True, decided_by="alice")
    assert ticket["status"] == "APPROVED"
    assert ticket["decided_by"] == "alice"
    assert ticket["execution_result"]["success"] is True
    assert ticket["execution_result"]["target"] == "wks-01"

    assert state.state_store.get_workflow(event_id)["status"] == "completed"
    history = [h["status"] for h in state.state_store.get_workflow_history(event_id)]
    assert history == [
        "received",
        "triage_in_progress",
        "paused_hitl",
        "response_in_progress",
        "completed",
    ]

    types = [e.event_type for e in state.audit_logger.entries]
    # The decision is audited before the action is authorized and executed.
    assert types.index("HITL_DECISION") < types.index("RESPONSE_EXECUTED")
    assert state.audit_logger.entries[types.index("HITL_DECISION")].actor == "alice"
    assert state.metrics.response_actions_executed == 1


def test_rejection_dismisses_without_executing():
    state = SentinelServerState(db_path=":memory:")
    event_id, ticket_id = _ingest(state)
    ticket = state.decide_ticket(ticket_id, approve=False)
    assert ticket["status"] == "REJECTED"
    assert ticket["execution_result"] is None
    workflow = state.state_store.get_workflow(event_id)
    assert workflow["status"] == "completed"
    assert workflow["detail"]["outcome"] == "dismissed"
    assert "RESPONSE_EXECUTED" not in [e.event_type for e in state.audit_logger.entries]


def test_ticket_cannot_be_decided_twice_or_when_missing():
    state = SentinelServerState(db_path=":memory:")
    _, ticket_id = _ingest(state)
    state.decide_ticket(ticket_id, approve=False)
    with pytest.raises(TicketStateError):
        state.decide_ticket(ticket_id, approve=True)
    with pytest.raises(TicketNotFoundError):
        state.decide_ticket("TICKET-nope", approve=True)


def test_approved_action_without_target_is_recorded_as_failed():
    state = SentinelServerState(db_path=":memory:")
    payload = {k: v for k, v in FINDING.items() if k != "device_hostname"}
    event_id, ticket_id = _ingest(state, payload)
    ticket = state.decide_ticket(ticket_id, approve=True)
    assert ticket["execution_result"]["success"] is False
    assert "host" in ticket["execution_result"]["message"]
    assert state.state_store.get_workflow(event_id)["status"] == "failed"
    assert state.metrics.response_actions_failed == 1


def test_non_escalated_event_completes():
    state = SentinelServerState(db_path=":memory:")
    event, _ = state.ingest_payload(
        {"class_uid": 3002, "activity_id": 1, "severity_id": 1, "user_name": "svc"}
    )
    workflow = state.state_store.get_workflow(event.get_event_id())
    assert workflow["status"] == "completed"
    assert workflow["detail"]["summary"]["requires_hitl"] is False
    assert state.state_store.list_hitl_tickets() == []


def test_hitl_webhook_notification_delivered():
    received = []

    class Receiver(BaseHTTPRequestHandler):
        def do_POST(self):
            received.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            self.send_response(204)
            self.end_headers()

        def log_message(self, *args):
            pass

    receiver = HTTPServer(("127.0.0.1", 0), Receiver)
    threading.Thread(target=receiver.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{receiver.server_address[1]}/hook"
        state = SentinelServerState(db_path=":memory:", hitl_notifier=HITLWebhookNotifier(url))
        _, ticket_id = _ingest(state)
    finally:
        receiver.shutdown()
        receiver.server_close()

    assert received[0]["ticket"]["ticket_id"] == ticket_id
    assert "HITL_NOTIFICATION_DELIVERED" in [e.event_type for e in state.audit_logger.entries]


def test_hitl_webhook_failure_is_audited_not_silent():
    notifier = HITLWebhookNotifier("http://127.0.0.1:9/hook", timeout_seconds=0.5, max_attempts=2)
    state = SentinelServerState(db_path=":memory:", hitl_notifier=notifier)
    _, ticket_id = _ingest(state)
    assert state.state_store.get_hitl_ticket(ticket_id)["status"] == "PENDING"
    assert "HITL_NOTIFICATION_FAILED" in [e.event_type for e in state.audit_logger.entries]
    assert state.metrics.hitl_delivery_failures == 1


def test_notifier_rejects_non_http_urls():
    with pytest.raises(SentinelError):
        HITLWebhookNotifier("file:///etc/passwd")
